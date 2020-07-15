from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class BaseRecord:
    created_by: str
    created_at: datetime
    updated_by: str
    updated_at: datetime


@dataclass(frozen=True)
class RawCveRecord(BaseRecord):
    cve_id: str
    cve_year: int
    cve_number: int
    cve_url: str
    cve_status: str
    cve_description: str
    cve_references: str
    phase: str
    votes: str
    comments: str

    def __eq__(self, other):
        if not isinstance(other, RawCveRecord):
            return False
        return (
            self.cve_id == other.cve_id
            and self.cve_year == other.cve_year
            and self.cve_number == other.cve_number
            and self.cve_url == other.cve_url
            and self.cve_status == other.cve_status
            and self.cve_description == other.cve_description
            and self.cve_references == other.cve_references
            and self.phase == other.phase
            and self.votes == other.votes
            and self.comments == other.comments
        )


@dataclass(frozen=True)
class RawNvdContentRecord(BaseRecord):
    cve_id: str
    cve_year: int
    cve_number: int
    nvd_url: str
    nvd_content_exists: bool
    http_status_code: int
    html_content: str
    last_fetched_date: datetime


@dataclass(frozen=True)
class DaemonStatusPersistenceRecord(BaseRecord):
    daemon_name: str
    daemon_status: dict


@dataclass(frozen=True)
class RawNvdRecord(BaseRecord):
    cve_id: str
    cve_year: int
    cve_number: int
    nvd_url: str
    current_description: str
    analysis_description: str
    cvss3_score: float
    cvss3_severity: str
    cvss3_vector: str
    cvss2_score: float
    cvss2_severity: str
    cvss2_vector: str
    nvd_published_date: datetime
    nvd_last_modified: datetime
    last_fetched_date: datetime
    last_scraped_date: datetime


@dataclass(frozen=True)
class NvdScrapeResult:
    current_description: str
    analysis_description: str
    cvss3_score: float
    cvss3_severity: str
    cvss3_vector: str
    cvss2_score: float
    cvss2_severity: str
    cvss2_vector: str
    nvd_published_date: datetime
    nvd_last_modified: datetime
    last_scraped_date: datetime


@dataclass(frozen=True)
class CveRecord(BaseRecord):
    cve_id: str
    cve_year: int
    cve_number: int
    cve_url: str
    nvd_url: str
    nvd_content_exists: bool
    cve_description: str
    cvss3_score: float
    cvss3_severity: str
    cvss3_vector: str
    cvss2_score: float
    cvss2_severity: str
    cvss2_vector: str
    published_date: datetime
    last_modified_date: datetime


@dataclass(frozen=True)
class CveFullTextSearchRecord(BaseRecord):
    id: int
    cve_id: str
    cve_text_for_search: str
