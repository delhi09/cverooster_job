CREATE TABLE raw_nvd_content
(
    cve_id VARCHAR(16) NOT NULL PRIMARY KEY,
    cve_year INT(11) NOT NULL,
    cve_number INT(11) NOT NULL,
    nvd_url VARCHAR(128) NOT NULL,
    nvd_content_exists TINYINT NOT NULL,
    http_status_code INT(11) NOT NULL,
    html_content LONGTEXT DEFAULT NULL,
    last_fetched_date DATETIME DEFAULT NULL,
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