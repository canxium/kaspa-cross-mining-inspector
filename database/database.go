package database

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/kaspa-live/kaspa-graph-inspector/database/model"
	"github.com/kaspa-live/kaspa-graph-inspector/database/utils/lrucache"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/pkg/errors"
)

type Database struct {
	database       *pg.DB
	blockBaseCache *lrucache.LRUCache[blockBase]
	sync.Mutex
}

// The cache capacity is set to embed ~1.5x the blocks provided
// by the node between the prunning point and the selected tip
const blockbaseCacheCapacity = 400000

type blockBase struct {
	ID     uint64
	Height uint64
}

func (bb *blockBase) Clone() *blockBase {
	return &blockBase{
		ID:     bb.ID,
		Height: bb.Height,
	}
}

func New(pgDatabase *pg.DB) *Database {
	database := &Database{
		database:       pgDatabase,
		blockBaseCache: lrucache.New[blockBase](blockbaseCacheCapacity, true),
	}
	return database
}

func (db *Database) RunInTransaction(transactionFunction func(*pg.Tx) error) error {
	db.Lock()
	defer db.Unlock()

	return db.database.RunInTransaction(context.Background(), transactionFunction)
}

// Load block infos into the memory cache for all blocks having a height geater or equal to minHeight
func (db *Database) LoadCache(databaseTransaction *pg.Tx, minHeight uint64) error {
	var results []struct {
		ID        uint64
		BlockHash string
		Height    uint64
	}
	_, err := databaseTransaction.Query(&results, "SELECT id, block_hash, height FROM blocks WHERE height >= ?", minHeight)
	if err != nil {
		return err
	}
	db.clearCache()
	for _, result := range results {
		blockHash, err := externalapi.NewDomainHashFromString(result.BlockHash)
		if err != nil {
			return err
		}

		bb := &blockBase{
			ID:     result.ID,
			Height: result.Height,
		}
		db.blockBaseCache.Add(blockHash, bb)
	}
	return nil
}

func (db *Database) clearCache() {
	db.blockBaseCache = lrucache.New[blockBase](blockbaseCacheCapacity, true)
}

func (db *Database) DoesBlockExist(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash) (bool, error) {
	// Search cache
	if db.blockBaseCache.Has(blockHash) {
		return true, nil
	}

	// Search database
	var results []blockBase

	_, err := databaseTransaction.Query(&results, "SELECT id, height FROM blocks WHERE block_hash = ?", blockHash.String())
	if err != nil {
		return false, err
	}
	if len(results) != 1 {
		return false, nil
	}
	db.blockBaseCache.Add(blockHash, results[0].Clone())

	return true, nil
}

func (db *Database) InsertBlock(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash, block *model.Block) error {
	_, err := db.database.Model(block).Insert()
	if err != nil {
		return err
	}

	bb := &blockBase{
		ID:     block.ID,
		Height: block.Height,
	}
	db.blockBaseCache.Add(blockHash, bb)

	return nil
}

func (db *Database) DoesMergeBlockExist(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash) (bool, error) {
	// Search cache
	if db.blockBaseCache.Has(blockHash) {
		return true, nil
	}

	// Search database
	var results []blockBase

	_, err := databaseTransaction.Query(&results, "SELECT id, height FROM blocks WHERE block_hash = ?", blockHash.String())
	if err != nil {
		return false, err
	}
	if len(results) != 1 {
		return false, nil
	}
	db.blockBaseCache.Add(blockHash, results[0].Clone())

	return true, nil
}

func (db *Database) InsertMergeBlock(block *model.MergeBlock) error {
	if _, err := db.database.Model(block).
		OnConflict("(block_hash) DO UPDATE").
		Set("difficulty = EXCLUDED.difficulty, miner = EXCLUDED.miner, tx_hash = EXCLUDED.tx_hash, tx_success = EXCLUDED.tx_success, tx_error = EXCLUDED.tx_error, is_valid_block = EXCLUDED.is_valid_block, timestamp = EXCLUDED.timestamp, gas_cap = EXCLUDED.gas_cap").
		Insert(); err != nil {
		return err
	}

	return nil
}

func (db *Database) DeleteMergeBlock(block *model.MergeBlock) error {
	if _, err := db.database.Exec("DELETE FROM merge_blocks WHERE block_hash = ?", block.BlockHash); err != nil {
		return err
	}

	return nil
}

func (db *Database) DeleteSuccessBlocks() error {
	if _, err := db.database.Exec("DELETE FROM merge_blocks WHERE tx_success = true"); err != nil {
		return err
	}

	return nil
}

func (db *Database) DeleteFailedBlocks() error {
	if _, err := db.database.Exec("DELETE from merge_blocks where is_valid_block = false and tx_error is not null"); err != nil {
		return err
	}

	return nil
}

func (db *Database) GetUnProcessMergeBlocks() (*[]model.MergeBlock, error) {
	result := new([]model.MergeBlock)
	_, err := db.database.Query(result, "SELECT * FROM merge_blocks WHERE miner is null and is_valid_block = true order by timestamp asc limit 100")
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (db *Database) GetPendingMergeBlocks(delayMilli int64, miner string, blockedMiners string) (*[]model.MergeBlock, error) {
	now := time.Now().UTC()
	timestamp := now.UnixMilli() - delayMilli
	result := new([]model.MergeBlock)
	if miner != "" {
		_, err := db.database.Query(result, "SELECT * FROM merge_blocks WHERE is_valid_block = true and tx_success = false and timestamp <= ? and LOWER(miner) = ? order by timestamp asc limit 30", timestamp, strings.ToLower(miner))
		if err != nil {
			return nil, err
		}
	} else if blockedMiners != "" {
		_, err := db.database.Query(result, "SELECT * FROM merge_blocks WHERE is_valid_block = true and tx_success = false and timestamp <= ? and LOWER(miner) NOT IN (?) order by timestamp asc limit 30", timestamp, pg.In(strings.Split(blockedMiners, ",")))
		if err != nil {
			return nil, err
		}
	} else {
		_, err := db.database.Query(result, "SELECT * FROM merge_blocks WHERE miner is not null and is_valid_block = true and tx_success = false and timestamp <= ? order by timestamp asc limit 30", timestamp)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (db *Database) CountBlockByMiner(address string) (uint64, error) {
	count, err := db.database.Model((*model.MergeBlock)(nil)).Where("miner = ?", address).Count()
	if err != nil {
		return 0, err
	}
	return uint64(count), nil
}

func (db *Database) IsExistSameBlockMinerAndTimeStamp(miner string, timestamp int64) bool {
	result := new(model.MergeBlock)
	_, err := db.database.QueryOne(result, "SELECT * FROM merge_blocks WHERE miner = ? and timestamp = ? and is_valid_block = true", miner, timestamp)
	if err != nil {
		return false
	}

	if result != nil && result.Miner == miner && result.Timestamp == timestamp {
		return true
	}

	return false
}

// GetBlock returns a block identified by `id`.
// Returns an error if the block `id` does not exist
func (db *Database) GetBlock(databaseTransaction *pg.Tx, id uint64) (*model.Block, error) {
	result := new(model.Block)
	_, err := databaseTransaction.QueryOne(result, "SELECT * FROM blocks WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (db *Database) UpdateBlockSelectedParent(databaseTransaction *pg.Tx, blockID uint64, selectedParentID uint64) error {
	_, err := databaseTransaction.Exec("UPDATE blocks SET selected_parent_id = ? WHERE id = ?", selectedParentID, blockID)
	return err
}

func (db *Database) UpdateBlockMergeSet(
	databaseTransaction *pg.Tx, blockID uint64, mergeSetRedIDs []uint64, mergeSetBlueIDs []uint64) error {

	_, err := databaseTransaction.Exec("UPDATE blocks SET merge_set_red_ids = ?, merge_set_blue_ids = ? WHERE id = ?",
		mergeSetRedIDs, mergeSetBlueIDs, blockID)
	return err
}

func (db *Database) UpdateBlockIsInVirtualSelectedParentChain(
	databaseTransaction *pg.Tx, blockIDsToIsInVirtualSelectedParentChain map[uint64]bool) error {

	for blockID, isInVirtualSelectedParentChain := range blockIDsToIsInVirtualSelectedParentChain {
		_, err := databaseTransaction.Exec("UPDATE blocks SET is_in_virtual_selected_parent_chain = ? WHERE id = ?",
			isInVirtualSelectedParentChain, blockID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *Database) UpdateBlockColors(databaseTransaction *pg.Tx, blockIDsToColors map[uint64]string) error {
	for blockID, color := range blockIDsToColors {
		_, err := databaseTransaction.Exec("UPDATE blocks SET color = ? WHERE id = ?", color, blockID)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateBlockDAAScores updates DAA Scores of block ids
func (db *Database) UpdateBlockDAAScores(databaseTransaction *pg.Tx, blockIDsToDAAScores map[uint64]uint64) error {
	for blockID, daaScore := range blockIDsToDAAScores {
		_, err := databaseTransaction.Exec("UPDATE blocks SET daa_score = ? WHERE id = ?", daaScore, blockID)
		if err != nil {
			return err
		}
	}
	return nil
}

// blockBaseByHash returns the id of a block idendified by `blockHash`.
// Returns an error if `blockHash` does not exist in the database
func (db *Database) BlockIDByHash(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash) (uint64, error) {
	bb, err := db.blockBaseByHash(databaseTransaction, blockHash)
	if err != nil {
		return 0, err
	}
	return bb.ID, err
}

// blockBaseByHash returns the height of a block idendified by `blockHash`.
// Returns an error if `blockHash` does not exist in the database
func (db *Database) BlockHeightByHash(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash) (uint64, error) {
	bb, err := db.blockBaseByHash(databaseTransaction, blockHash)
	if err != nil {
		return 0, err
	}
	return bb.Height, err
}

// blockBaseByHash returns a `blockBase` for a block idendified by `blockHash`.
// Returns an error if `blockHash` does not exist in the database
func (db *Database) blockBaseByHash(databaseTransaction *pg.Tx, blockHash *externalapi.DomainHash) (*blockBase, error) {
	// Search cache
	if cachedBlockBase, ok := db.blockBaseCache.Get(blockHash); ok {
		return cachedBlockBase, nil
	}

	// Search database
	var result blockBase
	_, err := databaseTransaction.QueryOne(&result, "SELECT id, height FROM blocks WHERE block_hash = ?", blockHash.String())
	if err != nil {
		return nil, errors.Wrapf(err, "block hash %s not found in blocks table", blockHash.String())
	}
	db.blockBaseCache.Add(blockHash, &result)

	return &result, nil
}

// BlockIDsByHashes returns an arrays of ids for `blockHashes` hashes.
// Returns an error if any hash in `blockHash` does not exist in the database
func (db *Database) BlockIDsByHashes(databaseTransaction *pg.Tx, blockHashes []*externalapi.DomainHash) ([]uint64, error) {
	blockIDs := make([]uint64, len(blockHashes))
	for i, blockHash := range blockHashes {
		blockID, err := db.BlockIDByHash(databaseTransaction, blockHash)
		if err != nil {
			return nil, err
		}
		blockIDs[i] = blockID
	}
	return blockIDs, nil
}

// BlockIDsAndHeightsByHashes returns two arrays, one of ids and one of heights
// for `blockHashes` hashes
func (db *Database) BlockIDsAndHeightsByHashes(databaseTransaction *pg.Tx, blockHashes []*externalapi.DomainHash) ([]uint64, []uint64, error) {
	blockIDs := make([]uint64, len(blockHashes))
	blockHeights := make([]uint64, len(blockHashes))
	for i, blockHash := range blockHashes {
		bb, err := db.blockBaseByHash(databaseTransaction, blockHash)
		if err != nil {
			return nil, nil, err
		}
		blockIDs[i] = bb.ID
		blockHeights[i] = bb.Height
	}
	return blockIDs, blockHeights, nil
}

// FindLatestStoredBlockIndex returns the index in a DAG ordered block hash
// array `blockHashes` of the latest block hash that is stored in the
// database
func (db *Database) FindLatestStoredBlockIndex(databaseTransaction *pg.Tx, blockHashes []*externalapi.DomainHash) (int, error) {
	// We use binary search since hash array is ordered from oldest to latest and
	// this ordering is also applied when storing blocks in the database
	low := int(0)
	high := int(len(blockHashes))
	for (high - low) > 1 {
		cur := (high + low) / 2
		hasBlock, err := db.DoesBlockExist(databaseTransaction, blockHashes[cur])
		if err != nil {
			return 0, err
		}
		if hasBlock {
			low = cur
		} else {
			high = cur
		}
	}
	return low, nil
}

// BlockIDByDAAScore returns the block ID of one block having the closest DAA
// score to `blockDAAScore`
func (db *Database) BlockIDByDAAScore(databaseTransaction *pg.Tx, blockDAAScore uint64) (uint64, error) {
	var result struct {
		ID uint64
	}
	_, err := databaseTransaction.QueryOne(&result, "SELECT id FROM blocks ORDER BY ABS(daa_score-(?)) LIMIT 1", blockDAAScore)
	if err != nil {
		return 0, err
	}
	return result.ID, nil
}

// BlockCountAtDAAScore returns the number of blocks having a DAA Score of `blockDAAScore`
func (db *Database) BlockCountAtDAAScore(databaseTransaction *pg.Tx, blockDAAScore uint64) (uint32, error) {
	var result struct {
		N uint32
	}
	_, err := databaseTransaction.Query(&result, "SELECT COUNT(*) AS N FROM blocks WHERE daa_score = (?)", blockDAAScore)
	if err != nil {
		return 0, err
	}
	return result.N, nil
}

func (db *Database) HighestBlockHeight(databaseTransaction *pg.Tx, blockIDs []uint64) (uint64, error) {
	var result struct {
		Highest uint64
	}
	_, err := databaseTransaction.Query(&result, "SELECT MAX(height) AS highest FROM blocks WHERE id IN (?)", pg.In(blockIDs))
	if err != nil {
		return 0, err
	}
	return result.Highest, nil
}

func (db *Database) HighestBlockInVirtualSelectedParentChain(databaseTransaction *pg.Tx) (*model.Block, error) {
	result := new(model.Block)
	_, err := databaseTransaction.Query(result, "select * from blocks where is_in_virtual_selected_parent_chain = ? order by height desc limit 1", true)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (db *Database) HeightGroupSize(databaseTransaction *pg.Tx, height uint64) (uint32, error) {
	var result struct {
		Size uint32
	}
	_, err := databaseTransaction.Query(&result, "SELECT size FROM height_groups WHERE height = ?", height)
	if err != nil {
		return 0, err
	}
	return result.Size, nil
}

func (db *Database) BlockHeight(databaseTransaction *pg.Tx, blockID uint64) (uint64, error) {
	var result struct {
		Height uint64
	}
	_, err := databaseTransaction.QueryOne(&result, "SELECT height FROM blocks WHERE id = ?", blockID)
	if err != nil {
		return 0, err
	}
	return result.Height, nil
}

func (db *Database) BlockHeightGroupIndex(databaseTransaction *pg.Tx, blockID uint64) (uint32, error) {
	var result struct {
		HeightGroupIndex uint32
	}
	_, err := databaseTransaction.QueryOne(&result, "SELECT height_group_index FROM blocks WHERE id = ?", blockID)
	if err != nil {
		return 0, err
	}
	return result.HeightGroupIndex, nil
}

func (db *Database) InsertEdge(databaseTransaction *pg.Tx, edge *model.Edge) error {
	_, err := databaseTransaction.Model(edge).Insert()
	if err != nil {
		return err
	}
	return nil
}

func (db *Database) InsertOrUpdateHeightGroup(databaseTransaction *pg.Tx, heightGroup *model.HeightGroup) error {
	_, err := databaseTransaction.Model(heightGroup).OnConflict("(height) DO UPDATE SET size = EXCLUDED.size").Insert()
	if err != nil {
		return err
	}
	return nil
}

func (db *Database) InsertCanxiumAccount(account *model.CanxiumAccount) error {
	if _, err := db.database.Model(account).Insert(); err != nil {
		return err
	}

	return nil
}

// GetAppConfig returns the stored app config.
// Returns an error if no app config does exist in the database.
func (db *Database) GetAppConfig(databaseTransaction *pg.Tx) (*model.AppConfig, error) {
	result := new(model.AppConfig)
	_, err := databaseTransaction.QueryOne(result, "SELECT * FROM appConfig")
	if err != nil {
		return nil, err
	}
	return result, nil
}

// StoreAppConfig stores an AppConfig in the database.
// ID is forced to true, this is the only accepted value by the database.
// Consequently, the database stores at most one AppConfig row.
func (db *Database) StoreAppConfig(databaseTransaction *pg.Tx, appConfig *model.AppConfig) error {
	appConfig.ID = true
	_, err := databaseTransaction.Model(appConfig).OnConflict("(id) DO UPDATE SET kaspad_version = EXCLUDED.kaspad_version, processing_version = EXCLUDED.processing_version, network = EXCLUDED.network").Insert()
	if err != nil {
		return err
	}
	return nil
}

func (db *Database) Clear(databaseTransaction *pg.Tx) error {
	db.clearCache()
	_, err := databaseTransaction.Exec("TRUNCATE TABLE blocks")
	if err != nil {
		return err
	}
	_, err = databaseTransaction.Exec("TRUNCATE TABLE edges")
	if err != nil {
		return err
	}
	_, err = databaseTransaction.Exec("TRUNCATE TABLE height_groups")
	return err
}

func (db *Database) Close() {
	db.Lock()
	defer db.Unlock()

	err := db.database.Close()
	if err != nil {
		log.Warnf("Could not close database: %s", err)
	}
}
