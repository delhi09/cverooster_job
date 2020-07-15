import configparser
import os

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.dialects.mysql import LONGTEXT as Longtext
from sqlalchemy.dialects.mysql import TINYINT as Tinyint


class Database:
    def __init__(self):
        self.config = configparser.ConfigParser()
        settings_file_path = "{}/cverooster/conf/settings.ini".format(
            os.environ["PYTHONPATH"]
        )
        self.config.read(settings_file_path)
        self.metadata = MetaData()
        self.engine = create_engine(
            "{dialect}://{user}:{password}@{host}:{port}/{db_name}".format(
                dialect=self.config["db_config"]["dialect"],
                user=self.config["db_config"]["user"],
                password=self.config["db_config"]["password"],
                host=self.config["db_config"]["host"],
                port=int(self.config["db_config"]["port"]),
                db_name=self.config["db_config"]["db_name"],
            )
        )
        self.metadata.create_all(self.engine)

    def get_connection(self):
        return self.engine.connect()

    def raw_cve(self):
        return Table(
            "raw_cve",
            self.metadata,
            Column("cve_id", String(32), nullable=False, primary_key=True),
            Column("cve_year", Integer, nullable=False),
            Column("cve_number", Integer, nullable=False),
            Column("cve_url", String(128), nullable=False),
            Column("cve_status", String(64), nullable=False),
            Column("cve_description", Text(), nullable=True),
            Column("cve_references", Text(), nullable=True),
            Column("phase", Text(), nullable=True),
            Column("votes", Text(), nullable=True),
            Column("comments", Text(), nullable=True),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def cve_year(self):
        return Table(
            "cve_year",
            self.metadata,
            Column("cve_year", Integer, nullable=False, primary_key=True),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def raw_nvd_content(self):
        return Table(
            "raw_nvd_content",
            self.metadata,
            Column("cve_id", String(32), nullable=False, primary_key=True),
            Column("cve_year", Integer, nullable=False),
            Column("cve_number", Integer, nullable=False),
            Column("nvd_url", String(128), nullable=False),
            Column("nvd_content_exists", Tinyint, nullable=False),
            Column("http_status_code", Integer, nullable=False),
            Column("html_content", Longtext, nullable=True),
            Column("last_fetched_date", DateTime, nullable=True),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def daemon_status_persistence(self):
        return Table(
            "daemon_status_persistence",
            self.metadata,
            Column("daemon_name", String(32), nullable=False, primary_key=True),
            Column("daemon_status", JSON, nullable=False),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def raw_nvd(self):
        return Table(
            "raw_nvd",
            self.metadata,
            Column("cve_id", String(32), nullable=False, primary_key=True),
            Column("cve_year", Integer, nullable=False),
            Column("cve_number", Integer, nullable=False),
            Column("nvd_url", String(128), nullable=False),
            Column("current_description", Text, nullable=True),
            Column("analysis_description", Text, nullable=True),
            Column("cvss3_score", Float, nullable=True),
            Column("cvss3_severity", String(16), nullable=True),
            Column("cvss3_vector", String(64), nullable=True),
            Column("cvss2_score", Float, nullable=True),
            Column("cvss2_severity", String(16), nullable=True),
            Column("cvss2_vector", String(64), nullable=True),
            Column("nvd_published_date", DateTime, nullable=True),
            Column("nvd_last_modified", DateTime, nullable=True),
            Column("last_fetched_date", DateTime, nullable=False),
            Column("last_scraped_date", DateTime, nullable=False),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def cve(self):
        return Table(
            "cve",
            self.metadata,
            Column("cve_id", String(32), nullable=False, primary_key=True),
            Column("cve_year", Integer, nullable=False),
            Column("cve_number", Integer, nullable=False),
            Column("cve_url", String(128), nullable=False),
            Column("nvd_url", String(128), nullable=False),
            Column("nvd_content_exists", Tinyint, nullable=False),
            Column("cve_description", Text, nullable=True),
            Column("cvss3_score", Float, nullable=True),
            Column("cvss3_severity", String(16), nullable=True),
            Column("cvss3_vector", String(64), nullable=True),
            Column("cvss2_score", Float, nullable=True),
            Column("cvss2_severity", String(16), nullable=True),
            Column("cvss2_vector", String(64), nullable=True),
            Column("published_date", DateTime, nullable=True),
            Column("last_modified_date", DateTime, nullable=True),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )

    def cve_full_text_search(self):
        return Table(
            "cve_full_text_search",
            self.metadata,
            Column("id", Integer, nullable=False, primary_key=True),
            Column("cve_id", String(32), nullable=False, unique=True),
            Column("cve_text_for_search", Text, nullable=False),
            Column("created_by", String(32), nullable=False),
            Column("created_at", DateTime, nullable=False),
            Column("updated_by", String(32), nullable=False),
            Column("updated_at", DateTime, nullable=False),
            extend_existing=True,
        )
