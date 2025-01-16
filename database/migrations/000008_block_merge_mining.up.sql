ALTER TABLE blocks
  ADD COLUMN merge_tx_signer TEXT NULL;
ALTER TABLE blocks
  ADD COLUMN merge_tx_nonce BIGINT NULL;
ALTER TABLE blocks
  ADD COLUMN merge_tx_raw TEXT NULL;
ALTER TABLE blocks
  ADD COLUMN merge_tx_hash TEXT NULL;
ALTER TABLE blocks
  ADD COLUMN merge_tx_success BOOLEAN DEFAULT FALSE NULL;