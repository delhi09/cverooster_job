CREATE TABLE cve_year
(
    cve_year INT(11) NOT NULL PRIMARY KEY,
    created_by VARCHAR(32) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_by VARCHAR(32) NOT NULL,
    updated_at DATETIME NOT NULL
)
ENGINE = InnoDB DEFAULT CHARACTER
SET = utf8
DEFAULT COLLATE = utf8_general_ci;