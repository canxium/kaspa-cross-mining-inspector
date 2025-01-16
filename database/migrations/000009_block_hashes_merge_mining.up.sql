CREATE TABLE merge_blocks
(
    id BIGSERIAL,
    block_hash CHAR(64) UNIQUE NOT NULL,
    difficulty BIGINT NULL,
    miner TEXT NULL,
    merge_tx_signer TEXT NULL,
    merge_tx_nonce BIGINT NULL,
    merge_tx_raw TEXT NULL,
    merge_tx_hash TEXT NULL,
    merge_tx_success BOOLEAN DEFAULT FALSE,
    is_valid_block BOOLEAN DEFAULT TRUE,
    timestamp BIGINT NOT NULL,
    PRIMARY KEY (id)
);