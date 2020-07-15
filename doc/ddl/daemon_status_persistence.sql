CREATE TABLE daemon_status_persistence
(
    daemon_name VARCHAR(32) NOT NULL PRIMARY KEY,
    daemon_status JSON NOT NULL,
    created_by VARCHAR(32) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_by VARCHAR(32) NOT NULL,
    updated_at DATETIME NOT NULL
)
ENGINE = InnoDB DEFAULT CHARACTER
SET = utf8
DEFAULT COLLATE = utf8_general_ci;