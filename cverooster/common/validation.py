import csv
import re

from cverooster.common.exception import CsvValidationError


class CveAllItemsCsvValidator:
    def __init__(self):
        self.cleaned_csv_file_name = None
        self.current_line = 0

    def validate(self, cleaned_csv_file_name):
        self.cleaned_csv_file_name = cleaned_csv_file_name
        with open(cleaned_csv_file_name, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for line, columns in enumerate(reader, start=1):
                self.current_line = line
                self._validate_column_len(columns)
                (
                    cve_id,
                    cve_status,
                    cve_description,
                    cve_references,
                    phase,
                    votes,
                    comments,
                ) = columns
                self._validate_cve_id(cve_id)
                self._validate_cve_status(cve_status)
                self._validate_cve_description(cve_description)

    def _validate_column_len(self, columns):
        expected = 7
        actual = len(columns)
        if actual != expected:
            error_message = f"カラム数が不正です。expected: {expected}, actual: {actual}"
            raise CsvValidationError(error_message, self.cleaned_csv_file_name)

    def _validate_cve_id(self, cve_id):
        if not re.match(r"^CVE-([0-9]{4})-([0-9]{4,})$", cve_id):
            error_message = f"CVE_IDのフォーマットが不正です。[{cve_id}]"
            raise CsvValidationError(
                error_message, self.cleaned_csv_file_name, self.current_line
            )

    def _validate_cve_status(self, cve_status):
        if not cve_status:
            raise Exception
        expected_cve_status = ("Candidate", "Entry")
        if not (cve_status in expected_cve_status):
            error_message = f"CVEの「Status」の値が期待していない文字列です。[{cve_status}]"
            raise CsvValidationError(
                error_message, self.cleaned_csv_file_name, self.current_line
            )

    def _validate_cve_description(self, cve_description):
        if not cve_description:
            error_message = f"CVEの「Description」が空です。[{cve_description}]"
            raise CsvValidationError(
                error_message, self.cleaned_csv_file_name, self.current_line
            )
