from datetime import datetime

from cverooster.common.data import CveRecord, DaemonStatusPersistenceRecord
from cverooster.common.exception import IllegalStateError
from cverooster.common.model import CveYear, DaemonStatusPersistence


class CveService:
    def create_cve_from_raw_cve(self, raw_cve, create_user, current_timestamp=None):
        if current_timestamp is None:
            current_timestamp = datetime.now()
        return CveRecord(
            cve_id=raw_cve.cve_id,
            cve_year=raw_cve.cve_year,
            cve_number=raw_cve.cve_number,
            cve_url=raw_cve.cve_url,
            nvd_url=None,
            nvd_content_exists=False,
            cve_description=raw_cve.cve_description,
            cvss3_score=None,
            cvss3_severity=None,
            cvss3_vector=None,
            cvss2_score=None,
            cvss2_severity=None,
            cvss2_vector=None,
            published_date=raw_cve.created_at,
            last_modified_date=raw_cve.created_at,
            created_by=create_user,
            created_at=current_timestamp,
            updated_by=create_user,
            updated_at=current_timestamp,
        )

    def create_cve_from_raw_cve_and_raw_nvd(
        self, raw_cve, raw_nvd, create_user, current_timestamp=None
    ):
        if current_timestamp is None:
            current_timestamp = datetime.now()
        cve_description = (
            raw_nvd.current_description
            if raw_nvd.current_description
            else raw_cve.cve_description
        )
        return CveRecord(
            cve_id=raw_cve.cve_id,
            cve_year=raw_cve.cve_year,
            cve_number=raw_cve.cve_number,
            cve_url=raw_cve.cve_url,
            nvd_url=raw_nvd.nvd_url,
            nvd_content_exists=True,
            cve_description=cve_description,
            cvss3_score=raw_nvd.cvss3_score,
            cvss3_severity=raw_nvd.cvss3_severity,
            cvss3_vector=raw_nvd.cvss3_vector,
            cvss2_score=raw_nvd.cvss2_score,
            cvss2_severity=raw_nvd.cvss2_severity,
            cvss2_vector=raw_nvd.cvss2_vector,
            published_date=raw_nvd.nvd_published_date,
            last_modified_date=raw_nvd.nvd_last_modified,
            created_by=create_user,
            created_at=current_timestamp,
            updated_by=create_user,
            updated_at=current_timestamp,
        )


class DaemonStatusService:
    def save_daemon_status(self, daemon_name, daemon_status):
        daemon_status_model = DaemonStatusPersistence()
        daemon_status_model.connect()
        daemon_status_model.begin_transaction()
        current_timestamp = datetime.now()
        daemon_status_model.save_daemon_status(
            DaemonStatusPersistenceRecord(
                daemon_name=daemon_name,
                daemon_status=daemon_status,
                created_by=daemon_name,
                created_at=current_timestamp,
                updated_by=daemon_name,
                updated_at=current_timestamp,
            )
        )
        daemon_status_model.commit()
        daemon_status_model.close_connection()

    def delete_daemon_status(self, daemon_name):
        daemon_status_model = DaemonStatusPersistence()
        daemon_status_model.connect()
        daemon_status_model.begin_transaction()
        daemon_status_model.delete_daemon_status(daemon_name)
        daemon_status_model.commit()
        daemon_status_model.close_connection()

    def read_daemon_status(self, daemon_name):
        daemon_status_model = DaemonStatusPersistence()
        daemon_status_model.connect()
        result = daemon_status_model.select_daemon_status(daemon_name)
        daemon_status_model.close_connection()
        return result


class CveYearService:
    def exists_cve_year(self, cve_year):
        cve_year_model = CveYear()
        cve_year_model.connect()
        cve_years = cve_year_model.select_all_cve_years_as_set()
        cve_year_model.close_connection()
        return cve_year in cve_years

    def has_prev_cve_year(self, current_cve_year):
        return self.exists_cve_year(current_cve_year - 1)

    def select_max_cve_year(self):
        cve_year_model = CveYear()
        cve_year_model.connect()
        max_cve_year = cve_year_model.select_max_cve_year()
        cve_year_model.close_connection()
        if max_cve_year is None:
            raise IllegalStateError("「cve_year」テーブルにレコードが存在しません。")
        return max_cve_year
