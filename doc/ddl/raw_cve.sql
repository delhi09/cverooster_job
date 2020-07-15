CREATE TABLE raw_cve
(
    cve_id VARCHAR(16) NOT NULL PRIMARY KEY,
    cve_year INT(11) NOT NULL,
    cve_number INT(11) NOT NULL,
    cve_url VARCHAR(128) NOT NULL,
    cve_status VARCHAR(16) NOT NULL,
    cve_description TEXT DEFAULT NULL,
    cve_references TEXT DEFAULT NULL,
    phase TEXT DEFAULT NULL,
    votes TEXT DEFAULT NULL,
    comments TEXT DEFAULT NULL,
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