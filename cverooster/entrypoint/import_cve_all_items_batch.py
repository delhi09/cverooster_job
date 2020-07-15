import argparse
import configparser
import csv
import logging
import logging.config
import os
import subprocess
import sys
import time
from datetime import datetime
from subprocess import CalledProcessError

from cverooster.common.data import RawCveRecord
from cverooster.common.exception import (
    BatchAbnormalTerminationError,
    DownloadFileFailedError,
    UnzippedFileNotExistsError,
)
from cverooster.common.model import CveYear, RawCve
from cverooster.common.util import parse_cve_id
from cverooster.common.validation import CveAllItemsCsvValidator

logging.config.fileConfig(
    "{}/cverooster/conf/logging.conf".format(os.environ["PYTHONPATH"])
)
logger = logging.getLogger("cveroosterBatchLogger")


class ImportCveAllItemsBatch:
    """raw_cveにcveデータをimportするバッチ

    raw_cveにcveデータをimportするバッチ。
    CVE公式が、以下のURLにてCVEの全てのアイテムのCSVデータを提供してくれているので、
    ダウンロードしてテーブルにimportする。
    https://cve.mitre.org/data/downloads/allitems.csv.gz

    ローカルでの実行時間は約40分。

    Raises:
        BatchAbnormalTerminationError: 異常終了時に投げられる例外
        UnzippedFileNotExistsError: 解凍したファイルが存在しない場合に投げられる例外
        DownloadFileFailedError: ファイルのダウンロードに失敗した場合に投げられる例外

    """

    BATCH_NAME = "import_cve_all_items_batch"

    def __init__(self):
        self.config = configparser.ConfigParser()
        settings_file_path = "{}/cverooster/conf/settings.ini".format(
            os.environ["PYTHONPATH"]
        )
        self.config.read(settings_file_path)
        self.cve_url_format = self.config["import_cve_all_items_batch"][
            "cve_url_format"
        ]

    def execute(self):
        try:
            batch_exec_timestamp = datetime.now()
            logger.info("%s started.", ImportCveAllItemsBatch.BATCH_NAME)
            options = self._parse_args()
            cleaned_csv_file_name = None
            if not options.cleaned_csv_file:
                gz_file_name = f"allitems.{batch_exec_timestamp:%Y%m%d%H%M%S}.csv.gz"
                url = self.config["import_cve_all_items_batch"]["cve_file_hosted_url"]
                retry = int(self.config["import_cve_all_items_batch"]["retry"])
                sleep = int(self.config["import_cve_all_items_batch"]["sleep_sec"])
                self._download_cve_allitems_csv_gz_retry(
                    url, gz_file_name, retry, sleep
                )
                unzipped_file_path = self._gunzip(gz_file_name)
                cleaned_csv_file_name = (
                    f"cleaned_allitems.{batch_exec_timestamp:%Y%m%d%H%M%S}.csv"
                )
                self._clean_csv(unzipped_file_path, cleaned_csv_file_name)
            else:
                logger.info(
                    "CSVのダウンロードをスキップして[%s]をDBにインポートします。", options.cleaned_csv_file
                )
                cleaned_csv_file_name = options.cleaned_csv_file
            validator = CveAllItemsCsvValidator()
            validator.validate(cleaned_csv_file_name)
            self._import_csv_into_db(cleaned_csv_file_name)
            self._import_csv_year_into_db(cleaned_csv_file_name)
            logger.info("%s successfully ended.", ImportCveAllItemsBatch.BATCH_NAME)
        except Exception as e:
            raise BatchAbnormalTerminationError(
                ImportCveAllItemsBatch.BATCH_NAME
            ) from e

    def _parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-f", "--cleaned_csv_file", help="specify cleaned_allitems.csv"
        )
        return parser.parse_args()

    def _import_csv_into_db(self, cleaned_csv_file_name):
        raw_cve = RawCve()
        raw_cve.connect()
        raw_cve.begin_transaction()
        line_count = self._count_lines(cleaned_csv_file_name)
        logger.info("DBへのimport処理を開始します。")
        import_start = datetime.now()
        with open(cleaned_csv_file_name, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for line_number, columns in enumerate(reader, start=1):
                (
                    cve_id,
                    cve_status,
                    cve_description,
                    cve_references,
                    phase,
                    votes,
                    comments,
                ) = columns
                cve_year, cve_number = parse_cve_id(cve_id)
                cve_url = self.cve_url_format.format(cve_id=cve_id)
                current_timestamp = datetime.now()
                save_data = RawCveRecord(
                    cve_id=cve_id,
                    cve_year=cve_year,
                    cve_number=cve_number,
                    cve_url=cve_url,
                    cve_status=cve_status,
                    cve_description=cve_description,
                    cve_references=cve_references,
                    phase=phase,
                    votes=votes,
                    comments=comments,
                    created_by=ImportCveAllItemsBatch.BATCH_NAME,
                    created_at=current_timestamp,
                    updated_by=ImportCveAllItemsBatch.BATCH_NAME,
                    updated_at=current_timestamp,
                )
                logger.info("%s/%s: [%s]処理中", line_number, line_count, save_data.cve_id)
                raw_cve.save_cve(save_data)
        raw_cve.commit()
        raw_cve.close_connection()
        import_elapsed_time = datetime.now() - import_start
        logger.info("DBへの保存処理が完了しました。処理時間: %s", import_elapsed_time)

    def _import_csv_year_into_db(self, cleaned_csv_file_name):
        cve_years = set()
        with open(cleaned_csv_file_name, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for columns in reader:
                cve_id = columns[0]
                cve_year, _ = parse_cve_id(cve_id)
                cve_years.add(cve_year)
        cve_year_model = CveYear()
        cve_year_model.connect()
        existing_cve_years = cve_year_model.select_all_cve_years_as_set()
        if cve_years == existing_cve_years:
            return
        new_cve_years = sorted(cve_years - existing_cve_years)
        cve_year_model.begin_transaction()
        for new_cve_year in new_cve_years:
            cve_year_model.insert_cve_year(
                new_cve_year, ImportCveAllItemsBatch.BATCH_NAME, datetime.now()
            )
        cve_year_model.commit()
        cve_year_model.close_connection()

    def _count_lines(self, cleaned_csv_file_name):
        line_count = 0
        with open(cleaned_csv_file_name, "r", encoding="utf-8") as f:
            for _ in f:
                line_count += 1
        return line_count

    def _clean_csv(self, raw_csv_path, cleaned_csv_output_path):
        start_line = 11
        line_number = 0
        with open(raw_csv_path, "r", encoding="utf-8", errors="replace") as fr:
            with open(cleaned_csv_output_path, "w", encoding="utf-8") as fw:
                for row in fr:
                    line_number += 1
                    if line_number < start_line:
                        continue
                    fw.write(row)

    def _gunzip(self, gz_file_path):
        cmd = f"gunzip {gz_file_path}"
        subprocess.run(cmd, shell=True, check=True)
        unzipped_file_path = gz_file_path.rstrip(".gz")
        if os.path.exists(unzipped_file_path):
            return unzipped_file_path
        else:
            raise UnzippedFileNotExistsError(unzipped_file_path)

    def _download_cve_allitems_csv_gz_retry(self, url, output_path, retry=3, sleep=1):
        for i in range(retry):
            logger.info("[%s]のダウンロードを開始します。%s回目)", url, i + 1)
            try:
                self._curl(url, output_path)
            except CalledProcessError as e:
                if i + 1 < retry:
                    logger.warning("[%s]のダウンロードに失敗しました。\n{e}", url, exc_info=True)
                    time.sleep(1)
                else:
                    raise DownloadFileFailedError(url, retry) from e
            else:
                logger.info("[%s]のダウンロードが完了しました。", url)
                break

    def _curl(self, url, output_path):
        cmd = f"curl -o {output_path} -f '{url}'"
        subprocess.run(cmd, shell=True, check=True)


def main():
    try:
        batch = ImportCveAllItemsBatch()
        batch.execute()
    except Exception as e:
        logger.exception(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
