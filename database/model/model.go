package model

import "time"

const (
	ColorGray = "gray"
	ColorRed  = "red"
	ColorBlue = "blue"
)

type Block struct {
	ID                             uint64   `pg:"id,pk"`
	BlockHash                      string   `pg:"block_hash"`
	Timestamp                      int64    `pg:"timestamp,use_zero"`
	ParentIDs                      []uint64 `pg:"parent_ids,use_zero"`
	DAAScore                       uint64   `pg:"daa_score,use_zero"`
	Height                         uint64   `pg:"height,use_zero"`
	HeightGroupIndex               uint32   `pg:"height_group_index,use_zero"`
	SelectedParentID               *uint64  `pg:"selected_parent_id"`
	Color                          string   `pg:"color"`
	IsInVirtualSelectedParentChain bool     `pg:"is_in_virtual_selected_parent_chain,use_zero"`
	MergeSetRedIDs                 []uint64 `pg:"merge_set_red_ids,use_zero"`
	MergeSetBlueIDs                []uint64 `pg:"merge_set_blue_ids,use_zero"`
}

type MergeBlock struct {
	ID         uint64 `pg:"id,pk"`
	BlockHash  string `pg:"block_hash"`
	Difficulty uint64 `pg:"difficulty"`
	Timestamp  int64  `pg:"timestamp,use_zero"`
	Miner      string `pg:"miner"`

	MergeTxHash    string `pg:"tx_hash"`
	MergeTxSuccess bool   `pg:"tx_success,use_zero"`
	TxError        string `pg:"tx_error"`

	IsValidBlock bool      `pg:"is_valid_block,use_zero"`
	GasCap       int64     `pg:"gas_cap,use_zero"`
	CreatedAt    time.Time `pg:"created_at"`
	DaaScore     uint64    `pg:"daa_score"`
}

type Edge struct {
	FromBlockID          uint64 `pg:"from_block_id,pk"`
	ToBlockID            uint64 `pg:"to_block_id,pk"`
	FromHeight           uint64 `pg:"from_height,use_zero"`
	ToHeight             uint64 `pg:"to_height,use_zero"`
	FromHeightGroupIndex uint32 `pg:"from_height_group_index,use_zero"`
	ToHeightGroupIndex   uint32 `pg:"to_height_group_index,use_zero"`
}

type HeightGroup struct {
	Height uint64 `pg:"height,use_zero"`
	Size   uint32 `pg:"size,use_zero"`
}

type AppConfig struct {
	//lint:ignore U1000 This field is used by gp-pg reflexively
	tableName struct{} `pg:"app_config,alias:app_config"`

	ID                bool   `pg:"id,pk"`
	KaspadVersion     string `pg:"kaspad_version"`
	ProcessingVersion string `pg:"processing_version"`
	Network           string `pg:"network"`
}

type CanxiumAccount struct {
	ID         uint64 `pg:"id,pk"`
	Address    string `pg:"address"`
	PrivateKey string `pg:"private_key"`
}
