CREATE TABLE raw_nvd
(
    cve_id VARCHAR(16) NOT NULL PRIMARY KEY,
    cve_year INT(11) NOT NULL,
    cve_number INT(11) NOT NULL,
    nvd_url VARCHAR(128) NOT NULL,
    current_description TEXT DEFAULT NULL,
    analysis_description TEXT DEFAULT NULL,
    cvss3_score FLOAT DEFAULT NULL,
    cvss3_severity VARCHAR(16) DEFAULT NULL,
    cvss3_vector VARCHAR(64) DEFAULT NULL,
    cvss2_score FLOAT DEFAULT NULL,
    cvss2_severity VARCHAR(16) DEFAULT NULL,
    cvss2_vector VARCHAR(64) DEFAULT NULL,
    nvd_published_date DATETIME DEFAULT NULL,
    nvd_last_modified DATETIME DEFAULT NULL,
    last_fetched_date DATETIME NOT NULL,
    last_scraped_date DATETIME NOT NULL,
    created_by VARCHAR(32) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_by VARCHAR(32) NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE unique_cve_number_cve_year
(cve_number, cve_year)
)
ENGINE = InnoDB DEFAULT CHARACTER
SET = utf8
DEFAULT COLLATE = utf8_general_ci;