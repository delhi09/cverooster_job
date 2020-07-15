from sqlalchemy import and_, delete, desc, select, update

from cverooster.common.data import (
    CveFullTextSearchRecord,
    CveRecord,
    DaemonStatusPersistenceRecord,
    RawCveRecord,
    RawNvdContentRecord,
    RawNvdRecord,
)
from cverooster.common.database import Database
from cverooster.common.exception import (
    ConnectionNotExistsError,
    TransactionNotExistsError,
)


class BaseModel:
    def __init__(self):
        self.database = Database()
        self.connection = None
        self.transaction = None

    def connect(self):
        self.connection = self.database.get_connection()

    def begin_transaction(self):
        if self.connection is not None:
            self.transaction = self.connection.begin()
        else:
            raise ConnectionNotExistsError

    def commit(self):
        if self.transaction is not None:
            self.transaction.commit()
        else:
            raise TransactionNotExistsError

    def rollback(self):
        if self.transaction is not None:
            self.transaction.rollback()
        else:
            raise TransactionNotExistsError

    def close_connection(self):
        if self.connection is not None:
            self.connection.close()

    def __del__(self):
        self.close_connection()


class RawCve(BaseModel):
    def _select_cve(self, cve_id):
        raw_cve = self.database.raw_cve()
        select_stmt = select([raw_cve]).where(raw_cve.c.cve_id == cve_id)
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return RawCveRecord(
            cve_id=result.cve_id,
            cve_year=result.cve_year,
            cve_number=result.cve_number,
            cve_url=result.cve_url,
            cve_status=result.cve_status,
            cve_description=result.cve_description,
            cve_references=result.cve_references,
            phase=result.phase,
            votes=result.votes,
            comments=result.comments,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def select_cve_ids(self, *, cve_year, cve_number_lt=None, limit):
        raw_cve = self.database.raw_cve()
        select_stmt = select([raw_cve.c.cve_id])
        if cve_number_lt is not None:
            select_stmt = select_stmt.where(
                and_(
                    raw_cve.c.cve_year == cve_year, raw_cve.c.cve_number < cve_number_lt
                )
            )
        else:
            select_stmt = select_stmt.where(raw_cve.c.cve_year == cve_year)
        select_stmt = select_stmt.limit(limit)
        select_stmt = select_stmt.order_by(desc(raw_cve.c.cve_number))
        rp = self.connection.execute(select_stmt)
        result = rp.fetchall()
        return [row.cve_id for row in result]

    def select_raw_cve_list(self, *, cve_year, cve_number_lt=None, limit):
        raw_cve = self.database.raw_cve()
        select_stmt = select([raw_cve])
        if cve_number_lt is not None:
            select_stmt = select_stmt.where(
                and_(
                    raw_cve.c.cve_year == cve_year, raw_cve.c.cve_number < cve_number_lt
                )
            )
        else:
            select_stmt = select_stmt.where(raw_cve.c.cve_year == cve_year)
        select_stmt = select_stmt.limit(limit)
        select_stmt = select_stmt.order_by(desc(raw_cve.c.cve_number))
        rp = self.connection.execute(select_stmt)
        result = rp.fetchall()
        raw_cve_list = []
        for row in result:
            raw_cve_list.append(
                RawCveRecord(
                    cve_id=row.cve_id,
                    cve_year=row.cve_year,
                    cve_number=row.cve_number,
                    cve_url=row.cve_url,
                    cve_status=row.cve_status,
                    cve_description=row.cve_description,
                    cve_references=row.cve_references,
                    phase=row.phase,
                    votes=row.votes,
                    comments=row.comments,
                    created_by=row.created_by,
                    created_at=row.created_at,
                    updated_by=row.updated_by,
                    updated_at=row.updated_at,
                )
            )
        return raw_cve_list

    def _insert_cve(self, save_data):
        raw_cve = self.database.raw_cve()
        insert_stmt = raw_cve.insert().values(
            cve_id=save_data.cve_id,
            cve_year=save_data.cve_year,
            cve_number=save_data.cve_number,
            cve_url=save_data.cve_url,
            cve_status=save_data.cve_status,
            cve_description=save_data.cve_description,
            cve_references=save_data.cve_references,
            phase=save_data.phase,
            votes=save_data.votes,
            comments=save_data.comments,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def _update_cve(self, save_data):
        raw_cve = self.database.raw_cve()
        update_stmt = (
            update(raw_cve)
            .where(raw_cve.c.cve_id == save_data.cve_id)
            .values(
                cve_year=save_data.cve_year,
                cve_number=save_data.cve_number,
                cve_url=save_data.cve_url,
                cve_status=save_data.cve_status,
                cve_description=save_data.cve_description,
                cve_references=save_data.cve_references,
                phase=save_data.phase,
                votes=save_data.votes,
                comments=save_data.comments,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def save_cve(self, save_data):
        existing_cve_data = self._select_cve(save_data.cve_id)
        if existing_cve_data is None:
            self._insert_cve(save_data)
        elif save_data != existing_cve_data:
            self._update_cve(save_data)
        else:
            pass


class CveYear(BaseModel):
    def select_all_cve_years_as_set(self):
        cve_year_model = self.database.cve_year()
        select_stmt = select([cve_year_model.c.cve_year])
        rp = self.connection.execute(select_stmt)
        result = rp.fetchall()
        if result is None:
            return set()
        cve_years = set()
        for row in result:
            cve_years.add(row.cve_year)
        return cve_years

    def select_max_cve_year(self):
        cve_years = self.select_all_cve_years_as_set()
        if not cve_years:
            return None
        return max(cve_years)

    def insert_cve_year(self, cve_year, created_by, created_at):
        cve_year_model = self.database.cve_year()
        insert_stmt = cve_year_model.insert().values(
            cve_year=cve_year,
            created_by=created_by,
            created_at=created_at,
            updated_by=created_by,
            updated_at=created_at,
        )
        self.connection.execute(insert_stmt)


class RawNvdContent(BaseModel):
    def _insert_nvd_content(self, save_data):
        raw_nvd_content = self.database.raw_nvd_content()
        insert_stmt = raw_nvd_content.insert().values(
            cve_id=save_data.cve_id,
            cve_year=save_data.cve_year,
            cve_number=save_data.cve_number,
            nvd_url=save_data.nvd_url,
            nvd_content_exists=save_data.nvd_content_exists,
            http_status_code=save_data.http_status_code,
            html_content=save_data.html_content,
            last_fetched_date=save_data.last_fetched_date,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def _update_nvd_content(self, save_data):
        raw_nvd_content = self.database.raw_nvd_content()
        update_stmt = (
            update(raw_nvd_content)
            .where(raw_nvd_content.c.cve_id == save_data.cve_id)
            .values(
                cve_year=save_data.cve_year,
                cve_number=save_data.cve_number,
                nvd_url=save_data.nvd_url,
                nvd_content_exists=save_data.nvd_content_exists,
                http_status_code=save_data.http_status_code,
                html_content=save_data.html_content,
                last_fetched_date=save_data.last_fetched_date,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def select_nvd_content(self, cve_id):
        raw_nvd_content = self.database.raw_nvd_content()
        select_stmt = select([raw_nvd_content]).where(
            raw_nvd_content.c.cve_id == cve_id
        )
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return RawNvdContentRecord(
            cve_id=result.cve_id,
            cve_year=result.cve_year,
            cve_number=result.cve_number,
            nvd_url=result.nvd_url,
            nvd_content_exists=result.nvd_content_exists,
            http_status_code=result.http_status_code,
            html_content=result.html_content,
            last_fetched_date=result.last_fetched_date,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def save_nvd_content(self, save_data):
        existing_nvd_content_data = self.select_nvd_content(save_data.cve_id)
        if existing_nvd_content_data is None:
            self._insert_nvd_content(save_data)
        else:
            self._update_nvd_content(save_data)

    def select_nvd_content_list(self, *, cve_year, cve_number_lt=None, limit):
        raw_nvd_content = self.database.raw_nvd_content()
        select_stmt = select([raw_nvd_content])
        if cve_number_lt is not None:
            select_stmt = select_stmt.where(
                and_(
                    raw_nvd_content.c.cve_year == cve_year,
                    raw_nvd_content.c.cve_number < cve_number_lt,
                )
            )
        else:
            select_stmt = select_stmt.where(raw_nvd_content.c.cve_year == cve_year)
        select_stmt = select_stmt.limit(limit)
        select_stmt = select_stmt.order_by(desc(raw_nvd_content.c.cve_number))
        rp = self.connection.execute(select_stmt)
        result = rp.fetchall()
        nvd_content_list = []
        for row in result:
            nvd_content_list.append(
                RawNvdContentRecord(
                    cve_id=row.cve_id,
                    cve_year=row.cve_year,
                    cve_number=row.cve_number,
                    nvd_url=row.nvd_url,
                    nvd_content_exists=row.nvd_content_exists,
                    http_status_code=row.http_status_code,
                    html_content=row.html_content,
                    last_fetched_date=row.last_fetched_date,
                    created_by=row.created_by,
                    created_at=row.created_at,
                    updated_by=row.updated_by,
                    updated_at=row.updated_at,
                )
            )
        return nvd_content_list


class DaemonStatusPersistence(BaseModel):
    def select_daemon_status(self, daemon_name):
        daemon_status = self.database.daemon_status_persistence()
        select_stmt = select([daemon_status]).where(
            daemon_status.c.daemon_name == daemon_name
        )
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return DaemonStatusPersistenceRecord(
            daemon_name=result.daemon_name,
            daemon_status=result.daemon_status,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def _insert_daemon_status(self, save_data):
        daemon_status = self.database.daemon_status_persistence()
        insert_stmt = daemon_status.insert().values(
            daemon_name=save_data.daemon_name,
            daemon_status=save_data.daemon_status,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def _update_daemon_status(self, save_data):
        daemon_status = self.database.daemon_status_persistence()
        update_stmt = (
            update(daemon_status)
            .where(daemon_status.c.daemon_name == save_data.daemon_name)
            .values(
                daemon_status=save_data.daemon_status,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def save_daemon_status(self, save_data):
        existing_daemon_status_data = self.select_daemon_status(save_data.daemon_name)
        if existing_daemon_status_data is None:
            self._insert_daemon_status(save_data)
        else:
            self._update_daemon_status(save_data)

    def delete_daemon_status(self, daemon_name):
        daemon_status = self.database.daemon_status_persistence()
        delete_stmt = delete(daemon_status).where(
            daemon_status.c.daemon_name == daemon_name
        )
        self.connection.execute(delete_stmt)


class RawNvd(BaseModel):
    def select_raw_nvd(self, cve_id):
        raw_nvd = self.database.raw_nvd()
        select_stmt = select([raw_nvd]).where(raw_nvd.c.cve_id == cve_id)
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return RawNvdRecord(
            cve_id=result.cve_id,
            cve_year=result.cve_year,
            cve_number=result.cve_number,
            nvd_url=result.nvd_url,
            current_description=result.current_description,
            analysis_description=result.analysis_description,
            cvss3_score=result.cvss3_score,
            cvss3_severity=result.cvss3_severity,
            cvss3_vector=result.cvss3_vector,
            cvss2_score=result.cvss2_score,
            cvss2_severity=result.cvss2_severity,
            cvss2_vector=result.cvss2_vector,
            nvd_published_date=result.nvd_published_date,
            nvd_last_modified=result.nvd_last_modified,
            last_fetched_date=result.last_fetched_date,
            last_scraped_date=result.last_scraped_date,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def _update_raw_nvd(self, save_data):
        raw_nvd = self.database.raw_nvd()
        update_stmt = (
            update(raw_nvd)
            .where(raw_nvd.c.cve_id == save_data.cve_id)
            .values(
                cve_year=save_data.cve_year,
                cve_number=save_data.cve_number,
                nvd_url=save_data.nvd_url,
                current_description=save_data.current_description,
                analysis_description=save_data.analysis_description,
                cvss3_score=save_data.cvss3_score,
                cvss3_severity=save_data.cvss3_severity,
                cvss3_vector=save_data.cvss3_vector,
                cvss2_score=save_data.cvss2_score,
                cvss2_severity=save_data.cvss2_severity,
                cvss2_vector=save_data.cvss2_vector,
                nvd_published_date=save_data.nvd_published_date,
                nvd_last_modified=save_data.nvd_last_modified,
                last_fetched_date=save_data.last_fetched_date,
                last_scraped_date=save_data.last_scraped_date,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def _insert_raw_nvd(self, save_data):
        raw_nvd = self.database.raw_nvd()
        insert_stmt = raw_nvd.insert().values(
            cve_id=save_data.cve_id,
            cve_year=save_data.cve_year,
            cve_number=save_data.cve_number,
            nvd_url=save_data.nvd_url,
            current_description=save_data.current_description,
            analysis_description=save_data.analysis_description,
            cvss3_score=save_data.cvss3_score,
            cvss3_severity=save_data.cvss3_severity,
            cvss3_vector=save_data.cvss3_vector,
            cvss2_score=save_data.cvss2_score,
            cvss2_severity=save_data.cvss2_severity,
            cvss2_vector=save_data.cvss2_vector,
            nvd_published_date=save_data.nvd_published_date,
            nvd_last_modified=save_data.nvd_last_modified,
            last_fetched_date=save_data.last_fetched_date,
            last_scraped_date=save_data.last_scraped_date,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def save_raw_nvd(self, save_data):
        existing_raw_nvd_data = self.select_raw_nvd(save_data.cve_id)
        if existing_raw_nvd_data is None:
            self._insert_raw_nvd(save_data)
        else:
            self._update_raw_nvd(save_data)


class Cve(BaseModel):
    def select_cve(self, cve_id):
        cve = self.database.cve()
        select_stmt = select([cve]).where(cve.c.cve_id == cve_id)
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return CveRecord(
            cve_id=result.cve_id,
            cve_year=result.cve_year,
            cve_number=result.cve_number,
            cve_url=result.cve_url,
            nvd_url=result.nvd_url,
            nvd_content_exists=result.nvd_content_exists,
            cve_description=result.cve_description,
            cvss3_score=result.cvss3_score,
            cvss3_severity=result.cvss3_severity,
            cvss3_vector=result.cvss3_vector,
            cvss2_score=result.cvss2_score,
            cvss2_severity=result.cvss2_severity,
            cvss2_vector=result.cvss2_vector,
            published_date=result.published_date,
            last_modified_date=result.last_modified_date,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def _update_cve(self, save_data):
        cve = self.database.cve()
        update_stmt = (
            update(cve)
            .where(cve.c.cve_id == save_data.cve_id)
            .values(
                cve_year=save_data.cve_year,
                cve_number=save_data.cve_number,
                cve_url=save_data.cve_url,
                nvd_url=save_data.nvd_url,
                nvd_content_exists=save_data.nvd_content_exists,
                cve_description=save_data.cve_description,
                cvss3_score=save_data.cvss3_score,
                cvss3_severity=save_data.cvss3_severity,
                cvss3_vector=save_data.cvss3_vector,
                cvss2_score=save_data.cvss2_score,
                cvss2_severity=save_data.cvss2_severity,
                cvss2_vector=save_data.cvss2_vector,
                published_date=save_data.published_date,
                last_modified_date=save_data.last_modified_date,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def _insert_cve(self, save_data):
        cve = self.database.cve()
        insert_stmt = cve.insert().values(
            cve_id=save_data.cve_id,
            cve_year=save_data.cve_year,
            cve_number=save_data.cve_number,
            cve_url=save_data.cve_url,
            nvd_url=save_data.nvd_url,
            nvd_content_exists=save_data.nvd_content_exists,
            cve_description=save_data.cve_description,
            cvss3_score=save_data.cvss3_score,
            cvss3_severity=save_data.cvss3_severity,
            cvss3_vector=save_data.cvss3_vector,
            cvss2_score=save_data.cvss2_score,
            cvss2_severity=save_data.cvss2_severity,
            cvss2_vector=save_data.cvss2_vector,
            published_date=save_data.published_date,
            last_modified_date=save_data.last_modified_date,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def save_cve(self, save_data):
        existing_cve_data = self.select_cve(save_data.cve_id)
        if existing_cve_data is None:
            self._insert_cve(save_data)
        else:
            self._update_cve(save_data)


class CveFullTextSearch(BaseModel):
    def select_cve_full_text_search(self, cve_id):
        cve_full_text_search = self.database.cve_full_text_search()
        select_stmt = select([cve_full_text_search]).where(
            cve_full_text_search.c.cve_id == cve_id
        )
        rp = self.connection.execute(select_stmt)
        result = rp.first()
        if result is None:
            return None
        return CveFullTextSearchRecord(
            id=result.id,
            cve_id=result.cve_id,
            cve_text_for_search=result.cve_text_for_search,
            created_by=result.created_by,
            created_at=result.created_at,
            updated_by=result.updated_by,
            updated_at=result.updated_at,
        )

    def _update_cve_full_text_search(self, save_data):
        cve_full_text_search = self.database.cve_full_text_search()
        update_stmt = (
            update(cve_full_text_search)
            .where(cve_full_text_search.c.cve_id == save_data.cve_id)
            .values(
                cve_id=save_data.cve_id,
                cve_text_for_search=save_data.cve_text_for_search,
                updated_by=save_data.updated_by,
                updated_at=save_data.updated_at,
            )
        )
        self.connection.execute(update_stmt)

    def _insert_cve_full_text_search(self, save_data):
        cve_full_text_search = self.database.cve_full_text_search()
        insert_stmt = cve_full_text_search.insert().values(
            cve_id=save_data.cve_id,
            cve_text_for_search=save_data.cve_text_for_search,
            created_by=save_data.created_by,
            created_at=save_data.created_at,
            updated_by=save_data.updated_by,
            updated_at=save_data.updated_at,
        )
        self.connection.execute(insert_stmt)

    def save_cve_full_text_search(self, save_data):
        existing_cve_full_text_search_data = self.select_cve_full_text_search(
            save_data.cve_id
        )
        if existing_cve_full_text_search_data is None:
            self._insert_cve_full_text_search(save_data)
        else:
            self._update_cve_full_text_search(save_data)
