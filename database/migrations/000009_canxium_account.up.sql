CREATE TABLE canxium_accounts
(
    id BIGSERIAL,
    address CHAR(42) UNIQUE NOT NULL,
    private_key CHAR(64) NULL,
    PRIMARY KEY (id)
);