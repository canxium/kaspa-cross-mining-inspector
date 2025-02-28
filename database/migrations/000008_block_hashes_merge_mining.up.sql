CREATE TABLE merge_blocks
(
    id BIGSERIAL,
    block_hash CHAR(64) UNIQUE NOT NULL,
    difficulty BIGINT NULL,
    miner TEXT NULL,
    tx_hash TEXT NULL,
    tx_success BOOLEAN DEFAULT FALSE,
    tx_error TEXT NULL,
    is_valid_block BOOLEAN DEFAULT TRUE,
    timestamp BIGINT NOT NULL,
    PRIMARY KEY (id)
);