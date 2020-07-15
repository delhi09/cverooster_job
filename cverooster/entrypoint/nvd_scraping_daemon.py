import argparse
import configparser
import json
import logging
import logging.config
import os
import sys
from datetime import datetime

from cverooster.common.data import RawNvdRecord
from cverooster.common.exception import (
    DaemonAbnormalTerminationError,
    IllegalStateError,
)
from cverooster.common.model import RawNvd, RawNvdContent
from cverooster.common.scraper import NvdScraper
from cverooster.common.service import CveYearService, DaemonStatusService
from cverooster.common.util import parse_cve_id

logging.config.fileConfig(
    "{}/cverooster/conf/logging.conf".format(os.environ["PYTHONPATH"])
)
logger = logging.getLogger("cveroosterBatchLogger")


class NvdScrapingDaemon:
    """NVDをスクレイピングするdaemon

    ※ 使用しないこと。
    理由はimport_raw_nvd.pyのコメントに記載。
    """

    DAEMON_NAME = "nvd_scraping_daemon"

    MODE_BATCH = "batch"

    MODE_DAEMON = "daemon"

    def __init__(self):
        self.config = configparser.ConfigParser()
        settings_file_path = "{}/cverooster/conf/settings.ini".format(
            os.environ["PYTHONPATH"]
        )
        self.config.read(settings_file_path)
        self.transaction_chunk = int(
            self.config["nvd_crawling_daemon"]["transaction_chunk"]
        )
        self.cve_year = None
        self.cve_number = None
        self.mode = None
        self.daemon_status_service = DaemonStatusService()
        self.cve_year_service = CveYearService()

    def start(self):
        try:
            logger.info("%s started.", NvdScrapingDaemon.DAEMON_NAME)
            options = self._parse_args()
            if options.mode and options.mode == NvdScrapingDaemon.MODE_BATCH:
                self.mode = NvdScrapingDaemon.MODE_BATCH
            else:
                self.mode = NvdScrapingDaemon.MODE_DAEMON
            if options.reset:
                self._reset_daemon_status(NvdScrapingDaemon.DAEMON_NAME)
            else:
                self._load_daemon_status(NvdScrapingDaemon.DAEMON_NAME)
            logger.info(
                "options: mode=%s, reset=%s", self.mode, options.reset,
            )
            self._run()
            logger.info("%s successfully ended.", NvdScrapingDaemon.DAEMON_NAME)
        except Exception as e:
            raise DaemonAbnormalTerminationError from e

    def _run(self):
        while True:
            nvd_content_list = self._select_target_nvd_content_list()
            logger.info(
                "処理対象のCVE_ID: [%s]", ", ".join([row.cve_id for row in nvd_content_list])
            )
            if not nvd_content_list:
                if self.mode == NvdScrapingDaemon.MODE_DAEMON:
                    logger.info(
                        "「cve_year=%s」のスクレイピングが完了したので、対象のcve_yearを変更します。", self.cve_year
                    )
                    self._change_target_year()
                    logger.info(
                        "対象のcve_yearを変更しました。対象: cve_year=%s, cve_number=%s",
                        self.cve_year,
                        self.cve_number,
                    )
                    continue
                elif self.mode == NvdScrapingDaemon.MODE_BATCH:
                    if self.cve_year_service.has_prev_cve_year(self.cve_year):
                        logger.info(
                            "「cve_year=%s」のスクレイピングが完了したので、対象のcve_yearを変更します。",
                            self.cve_year,
                        )
                        self._back_cve_year()
                        logger.info(
                            "対象のcve_yearを変更しました。対象: cve_year=%s, cve_number=%s",
                            self.cve_year,
                            self.cve_number,
                        )
                        continue
                    else:
                        logger.info(
                            "「cve_year=%s」のスクレイピングが完了しました。%sは処理対象外なので、バッチ処理を終了します。",
                            self.cve_year,
                            self.cve_year - 1,
                        )
                        break
                else:
                    raise IllegalStateError(f"定義されていないmodeです。mode={self.mode}")
            raw_nvd_list = self._scrape_nvd_content_list(nvd_content_list)
            self._save_raw_nvd_list(raw_nvd_list)
            self._update_status(nvd_content_list[-1].cve_id)

    def _update_status(self, last_processed_cve_id):
        _, cve_number = parse_cve_id(last_processed_cve_id)
        self.cve_number = cve_number
        self.daemon_status_service.save_daemon_status(
            NvdScrapingDaemon.DAEMON_NAME,
            json.dumps({"cve_year": self.cve_year, "cve_number": self.cve_number}),
        )

    def _save_raw_nvd_list(self, raw_nvd_list):
        raw_nvd_model = RawNvd()
        raw_nvd_model.connect()
        raw_nvd_model.begin_transaction()
        for raw_nvd in raw_nvd_list:
            raw_nvd_model.save_raw_nvd(raw_nvd)
        raw_nvd_model.commit()
        raw_nvd_model.close_connection()

    def _scrape_nvd_content_list(self, nvd_content_list):
        raw_nvd_list = []
        for nvd_content in nvd_content_list:
            scraper = NvdScraper(nvd_content.nvd_url, nvd_content.html_content)
            scrape_result = scraper.scrape()
            current_timestamp = datetime.now()
            raw_nvd_list.append(
                RawNvdRecord(
                    cve_id=nvd_content.cve_id,
                    cve_year=nvd_content.cve_year,
                    cve_number=nvd_content.cve_number,
                    nvd_url=nvd_content.nvd_url,
                    current_description=scrape_result.current_description,
                    analysis_description=scrape_result.analysis_description,
                    cvss3_score=scrape_result.cvss3_score,
                    cvss3_severity=scrape_result.cvss3_severity,
                    cvss3_vector=scrape_result.cvss3_vector,
                    cvss2_score=scrape_result.cvss2_score,
                    cvss2_severity=scrape_result.cvss2_severity,
                    cvss2_vector=scrape_result.cvss2_vector,
                    nvd_published_date=scrape_result.nvd_published_date,
                    nvd_last_modified=scrape_result.nvd_last_modified,
                    last_fetched_date=nvd_content.last_fetched_date,
                    last_scraped_date=scrape_result.last_scraped_date,
                    created_by=NvdScrapingDaemon.DAEMON_NAME,
                    created_at=current_timestamp,
                    updated_by=NvdScrapingDaemon.DAEMON_NAME,
                    updated_at=current_timestamp,
                )
            )
        return raw_nvd_list

    def _select_target_nvd_content_list(self):
        raw_nvd_content_model = RawNvdContent()
        raw_nvd_content_model.connect()
        nvd_content_list = raw_nvd_content_model.select_nvd_content_list(
            cve_year=self.cve_year,
            cve_number_lt=self.cve_number,
            limit=self.transaction_chunk,
        )
        raw_nvd_content_model.close_connection()
        return nvd_content_list

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

    def _change_target_year(self):
        if self.cve_year_service.has_prev_cve_year(self.cve_year):
            self.cve_year -= 1
            self.cve_number = None
        else:
            self.cve_year = self.cve_year_service.select_max_cve_year()
            self.cve_number = None

    def _back_cve_year(self):
        self.cve_year -= 1
        self.cve_number = None

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


def main():
    try:
        daemon = NvdScrapingDaemon()
        daemon.start()
    except Exception as e:
        logger.exception(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
