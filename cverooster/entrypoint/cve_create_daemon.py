import argparse
import configparser
import json
import logging
import logging.config
import os
import sys
from datetime import datetime

from cverooster.common.data import CveFullTextSearchRecord
from cverooster.common.exception import (
    DaemonAbnormalTerminationError,
    IllegalStateError,
)
from cverooster.common.model import Cve, CveFullTextSearch, RawCve, RawNvd
from cverooster.common.service import CveService, CveYearService, DaemonStatusService
from cverooster.common.util import parse_cve_id

logging.config.fileConfig(
    "{}/cverooster/conf/logging.conf".format(os.environ["PYTHONPATH"])
)
logger = logging.getLogger("cveroosterBatchLogger")


class CveCreateDaemon:
    """raw_cveとraw_nvdのデータを元にcveテーブルにデータを作成するdaemon

    Raises:
        DaemonAbnormalTerminationError: 異常終了時に投げられる例外
        IllegalStateError: 状態異常時に投げられる例外
    """

    DAEMON_NAME = "cve_create_daemon"

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
        self.cve_service = CveService()
        self.daemon_status_service = DaemonStatusService()
        self.cve_year_service = CveYearService()

    def start(self):
        try:
            logger.info("%s started.", CveCreateDaemon.DAEMON_NAME)
            options = self._parse_args()
            if options.mode and options.mode == CveCreateDaemon.MODE_BATCH:
                self.mode = CveCreateDaemon.MODE_BATCH
            else:
                self.mode = CveCreateDaemon.MODE_DAEMON
            if options.reset:
                self._reset_daemon_status(CveCreateDaemon.DAEMON_NAME)
            else:
                self._load_daemon_status(CveCreateDaemon.DAEMON_NAME)
            logger.info(
                "options: mode=%s, reset=%s", self.mode, options.reset,
            )
            self._run()
        except Exception as e:
            raise DaemonAbnormalTerminationError from e

    def _run(self):
        while True:
            raw_cve_list = self._select_target_raw_cve_list()
            logger.info(
                "処理対象のCVE_ID: [%s]", ", ".join([row.cve_id for row in raw_cve_list])
            )
            if not raw_cve_list:
                if self.mode == CveCreateDaemon.MODE_DAEMON:
                    logger.info(
                        "「cve_year=%s」の処理が完了したので、対象のcve_yearを変更します。", self.cve_year
                    )
                    self._change_target_year()
                    logger.info(
                        "対象のcve_yearを変更しました。対象: cve_year=%s, cve_number=%s",
                        self.cve_year,
                        self.cve_number,
                    )
                    continue
                elif self.mode == CveCreateDaemon.MODE_BATCH:
                    if self.cve_year_service.has_prev_cve_year(self.cve_year):
                        logger.info(
                            "「cve_year=%s」の処理が完了したので、対象のcve_yearを変更します。", self.cve_year,
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
                            "「cve_year=%s」の処理が完了しました。%sは処理対象外なので、バッチ処理を終了します。",
                            self.cve_year,
                            self.cve_year - 1,
                        )
                        break
                else:
                    raise IllegalStateError(f"定義されていないmodeです。mode={self.mode}")
            cve_list = self._create_cve_list(raw_cve_list)
            self._save_cve_list(cve_list)
            cve_full_text_search_list = self._create_cve_full_text_search_list(cve_list)
            self._save_cve_full_text_search(cve_full_text_search_list)
            self._update_status(raw_cve_list[-1].cve_id)

    def _save_cve_full_text_search(self, cve_full_text_search_list):
        cve_full_text_search_model = CveFullTextSearch()
        cve_full_text_search_model.connect()
        cve_full_text_search_model.begin_transaction()
        for cve_full_text_search in cve_full_text_search_list:
            cve_full_text_search_model.save_cve_full_text_search(cve_full_text_search)
        cve_full_text_search_model.commit()
        cve_full_text_search_model.close_connection()

    def _create_cve_full_text_search_list(self, cve_list):
        cve_full_text_search_list = []
        for cve in cve_list:
            current_timestamp = datetime.now()
            cve_full_text_search_list.append(
                CveFullTextSearchRecord(
                    id=None,
                    cve_id=cve.cve_id,
                    cve_text_for_search=cve.cve_description,
                    created_by=CveCreateDaemon.DAEMON_NAME,
                    created_at=current_timestamp,
                    updated_by=CveCreateDaemon.DAEMON_NAME,
                    updated_at=current_timestamp,
                )
            )
        return cve_full_text_search_list

    def _update_status(self, last_processed_cve_id):
        _, cve_number = parse_cve_id(last_processed_cve_id)
        self.cve_number = cve_number
        self.daemon_status_service.save_daemon_status(
            CveCreateDaemon.DAEMON_NAME,
            json.dumps({"cve_year": self.cve_year, "cve_number": self.cve_number}),
        )

    def _change_target_year(self):
        if self.cve_year_service.has_prev_cve_year(self.cve_year):
            self.cve_year -= 1
            self.cve_number = None
        else:
            self.cve_year = self.cve_year_service.select_max_cve_year()
            self.cve_number = None

    def _save_cve_list(self, cve_list):
        cve_model = Cve()
        cve_model.connect()
        cve_model.begin_transaction()
        for cve in cve_list:
            cve_model.save_cve(cve)
        cve_model.commit()
        cve_model.close_connection()

    def _validate_required_values(self, raw_cve, raw_nvd):
        if not raw_cve.cve_description and not raw_nvd.current_description:
            logger.warning(
                "[raw_cve.cve_description]と[raw_nvd.current_description]が共にemptyです。CVE_ID=%s",
                raw_cve.cve_id,
            )
            return False
        return True

    def _create_cve_list(self, raw_cve_list):
        cve_list = []
        for raw_cve in raw_cve_list:
            raw_nvd = self._select_raw_nvd(raw_cve.cve_id)
            if not self._validate_required_values(raw_cve, raw_nvd):
                continue
            cve = None
            if raw_nvd is None:
                cve = self.cve_service.create_cve_from_raw_cve(
                    raw_cve, CveCreateDaemon.DAEMON_NAME
                )
            else:
                cve = self.cve_service.create_cve_from_raw_cve_and_raw_nvd(
                    raw_cve, raw_nvd, CveCreateDaemon.DAEMON_NAME
                )
            cve_list.append(cve)
        return cve_list

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

    def _select_target_raw_cve_list(self):
        raw_cve_model = RawCve()
        raw_cve_model.connect()
        raw_cve_list = raw_cve_model.select_raw_cve_list(
            cve_year=self.cve_year,
            cve_number_lt=self.cve_number,
            limit=self.transaction_chunk,
        )
        raw_cve_model.close_connection()
        return raw_cve_list

    def _select_raw_nvd(self, cve_id):
        raw_nvd_model = RawNvd()
        raw_nvd_model.connect()
        raw_nvd = raw_nvd_model.select_raw_nvd(cve_id)
        raw_nvd_model.close_connection()
        return raw_nvd

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

    def _back_cve_year(self):
        self.cve_year -= 1
        self.cve_number = None


def main():
    try:
        daemon = CveCreateDaemon()
        daemon.start()
    except Exception as e:
        logger.exception(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
