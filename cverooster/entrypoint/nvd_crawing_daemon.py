import argparse
import configparser
import json
import logging
import logging.config
import os
import ssl
import sys
import time
import urllib.robotparser
from datetime import datetime

import requests

from cverooster.common.data import RawNvdContentRecord
from cverooster.common.exception import (
    AccessControlConfiguredError,
    CrawlForbiddenError,
    DaemonAbnormalTerminationError,
    IllegalStateError,
)
from cverooster.common.model import RawCve, RawNvdContent
from cverooster.common.service import CveYearService, DaemonStatusService
from cverooster.common.util import parse_cve_id

# 開発環境用の設定
ssl._create_default_https_context = ssl._create_unverified_context
logging.config.fileConfig(
    "{}/cverooster/conf/logging.conf".format(os.environ["PYTHONPATH"])
)
logger = logging.getLogger("cveroosterBatchLogger")


class NvdCrawlingDaemon:
    """NVDをクロールするdaemon

    ※ 使用しないこと。
    理由はimport_raw_nvd.pyのコメントに記載。
    """

    DAEMON_NAME = "nvd_crawling_daemon"

    MODE_BATCH = "batch"

    MODE_DAEMON = "daemon"

    def __init__(self):
        self.config = configparser.ConfigParser()
        settings_file_path = "{}/cverooster/conf/settings.ini".format(
            os.environ["PYTHONPATH"]
        )
        self.config.read(settings_file_path)
        self.nvd_url_format = self.config["nvd_crawling_daemon"]["nvd_url_format"]
        self.retry = int(self.config["nvd_crawling_daemon"]["retry"])
        self.sleep_sec = int(self.config["nvd_crawling_daemon"]["sleep_sec"])
        self.transaction_chunk = int(
            self.config["nvd_crawling_daemon"]["transaction_chunk"]
        )
        self.cve_year_lower_limit = int(
            self.config["nvd_crawling_daemon"]["cve_year_lower_limit"]
        )
        self.cve_year = None
        self.cve_number = None
        self.mode = None
        self.daemon_status_service = DaemonStatusService()
        self.cve_year_service = CveYearService()

        self.robotstxt_url = self.config["nvd_crawling_daemon"]["nvd_robotstxt_url"]
        self.robotparser = self._configure_robotparser()

    def start(self):
        try:
            logger.info("%s started.", NvdCrawlingDaemon.DAEMON_NAME)
            options = self._parse_args()
            if options.mode and options.mode == NvdCrawlingDaemon.MODE_BATCH:
                self.mode = NvdCrawlingDaemon.MODE_BATCH
            else:
                self.mode = NvdCrawlingDaemon.MODE_DAEMON
            if options.reset:
                self._reset_daemon_status(NvdCrawlingDaemon.DAEMON_NAME)
            else:
                self._load_daemon_status(NvdCrawlingDaemon.DAEMON_NAME)
            logger.info(
                "options: mode=%s, reset=%s", self.mode, options.reset,
            )
            self._run()
            logger.info("%s successfully ended.", NvdCrawlingDaemon.DAEMON_NAME)
        except Exception as e:
            raise DaemonAbnormalTerminationError from e

    def _run(self):
        while True:
            self.robotparser = self._configure_robotparser()
            if self._is_acl_configured():
                raise AccessControlConfiguredError(self.robotstxt_url)
            cve_ids = self._select_target_cve_ids()
            logger.info("処理対象のCVE_ID: [%s]", ", ".join(cve_ids))
            if not cve_ids:
                if self.mode == NvdCrawlingDaemon.MODE_DAEMON:
                    logger.info(
                        "「cve_year=%s」のクロールが完了したので、対象のcve_yearを変更します。", self.cve_year
                    )
                    self._change_target_year()
                    logger.info(
                        "対象のcve_yearを変更しました。対象: cve_year=%s, cve_number=%s",
                        self.cve_year,
                        self.cve_number,
                    )
                    continue
                elif self.mode == NvdCrawlingDaemon.MODE_BATCH:
                    if self.cve_year_service.has_prev_cve_year(self.cve_year):
                        logger.info(
                            "「cve_year=%s」のクロールが完了したので、対象のcve_yearを変更します。",
                            self.cve_year,
                        )
                        self._back_target_year()
                        logger.info(
                            "対象のcve_yearを変更しました。対象: cve_year=%s, cve_number=%s",
                            self.cve_year,
                            self.cve_number,
                        )
                        continue
                    else:
                        logger.info(
                            "「cve_year=%s」のクロールが完了しました。%sは処理対象外なので、バッチ処理を終了します。",
                            self.cve_year,
                            self.cve_year - 1,
                        )
                        break
                else:
                    raise IllegalStateError(f"定義されていないmodeです。mode={self.mode}")

            crawl_result_list = self._crawl_nvd_urls(cve_ids)
            self._save_crawl_result_list(crawl_result_list)
            self._update_status(cve_ids[-1])

    def _update_status(self, last_processed_cve_id):
        _, cve_number = parse_cve_id(last_processed_cve_id)
        self.cve_number = cve_number
        self.daemon_status_service.save_daemon_status(
            NvdCrawlingDaemon.DAEMON_NAME,
            json.dumps({"cve_year": self.cve_year, "cve_number": self.cve_number}),
        )

    def _configure_robotparser(self):
        robotparser = urllib.robotparser.RobotFileParser()
        robotparser.set_url(self.robotstxt_url)
        robotparser.read()
        return robotparser

    def _is_acl_configured(self):
        request_rate = self.robotparser.request_rate("*")
        delay = self.robotparser.crawl_delay("*")
        if request_rate is None and delay is None:
            return False
        else:
            return True

    def _is_fetch_enabled(self, url):
        return self.robotparser.can_fetch("*", url)

    def _parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-r",
            "--reset",
            action="store_true",
            help="reset daemon status saved on DB.",
        )
        parser.add_argument(
            "-m",
            "--mode",
            help="[daemon(default)]: run daemon mode.[batch]: run batch mode.",
        )
        return parser.parse_args()

    def _crawl_nvd_urls(self, cve_ids):
        crawl_result_list = []
        for cve_id in cve_ids:
            http_status_code = None
            html_content = None
            nvd_url = self.nvd_url_format.format(cve_id=cve_id)
            if not self._is_fetch_enabled(nvd_url):
                raise CrawlForbiddenError(nvd_url, self.robotstxt_url)
            cve_year, cve_number = parse_cve_id(cve_id)
            for i in range(self.retry):
                logger.info("%s秒スリープします。", self.sleep_sec)
                time.sleep(self.sleep_sec)
                logger.info("[%s]へのリクエストを開始します。(%s回目)", nvd_url, i + 1)
                http_status_code, html_content = self._fetch_content(nvd_url)
                if http_status_code == requests.codes.ok:
                    logger.info(
                        "[%s]へのリクエストが完了しました。http_status_code=%s",
                        nvd_url,
                        http_status_code,
                    )
                    break
                else:
                    logger.warning(
                        "[%s]へのリクエストにおいて、%s以外のhttp_status_codeが返されました。http_status_code=%s",
                        nvd_url,
                        requests.codes.ok,
                        http_status_code,
                    )
            nvd_content_exists = (
                True if http_status_code == requests.codes.ok else False
            )
            current_timestamp = datetime.now()
            crawl_result_list.append(
                RawNvdContentRecord(
                    cve_id=cve_id,
                    cve_year=cve_year,
                    cve_number=cve_number,
                    nvd_url=nvd_url,
                    nvd_content_exists=nvd_content_exists,
                    http_status_code=http_status_code,
                    html_content=html_content,
                    last_fetched_date=current_timestamp,
                    created_by=NvdCrawlingDaemon.DAEMON_NAME,
                    created_at=current_timestamp,
                    updated_by=NvdCrawlingDaemon.DAEMON_NAME,
                    updated_at=current_timestamp,
                )
            )
        return crawl_result_list

    def _save_crawl_result_list(self, crawl_result_list):
        raw_nvd_content_model = RawNvdContent()
        raw_nvd_content_model.connect()
        raw_nvd_content_model.begin_transaction()
        for raw_nvd_content in crawl_result_list:
            raw_nvd_content_model.save_nvd_content(raw_nvd_content)
        raw_nvd_content_model.commit()
        raw_nvd_content_model.close_connection()

    def _fetch_content(self, nvd_url):
        response = requests.get(nvd_url)
        return response.status_code, response.text

    def _reset_daemon_status(self, daemon_name):
        self.daemon_status_service.delete_daemon_status(daemon_name)
        self.cve_year = self.cve_year_service.select_max_cve_year()
        self.cve_number = None

    def _load_daemon_status(self, daemon_name):
        result = self.daemon_status_service.read_daemon_status(daemon_name)
        if result is None:
            self.cve_year = self.cve_year_service.select_max_cve_year()
            return
        daemon_status = json.loads(result.daemon_status)
        if "cve_year" not in daemon_status:
            raise IllegalStateError(
                f"daemon_statusに「cve_year」が定義されていません。daemon_status: {daemon_status}"
            )
        if "cve_number" not in daemon_status:
            raise IllegalStateError(
                f"daemon_statusに「cve_number」が定義されていません。daemon_status: {daemon_status}"
            )
        self.cve_year = daemon_status["cve_year"]
        self.cve_number = daemon_status["cve_number"]

    def _select_target_cve_ids(self):
        raw_cve_model = RawCve()
        raw_cve_model.connect()
        target_cve_ids = raw_cve_model.select_cve_ids(
            cve_year=self.cve_year,
            cve_number_lt=self.cve_number,
            limit=self.transaction_chunk,
        )
        raw_cve_model.close_connection()
        return target_cve_ids

    def _change_target_year(self):
        if self.cve_year_service.has_prev_cve_year(self.cve_year):
            self.cve_year -= 1
            self.cve_number = None
        else:
            self.cve_year = self.cve_year_service.select_max_cve_year()
            self.cve_number = None

    def _back_target_year(self):
        self.cve_year -= 1
        self.cve_number = None


def main():
    try:
        daemon = NvdCrawlingDaemon()
        daemon.start()
    except Exception as e:
        logger.exception(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
