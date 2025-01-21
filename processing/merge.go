package processing

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	databasePackage "github.com/kaspa-live/kaspa-graph-inspector/database"
	"github.com/kaspa-live/kaspa-graph-inspector/database/model"
	configPackage "github.com/kaspa-live/kaspa-graph-inspector/infrastructure/config"
	"github.com/kaspa-live/kaspa-graph-inspector/infrastructure/logging"
	versionPackage "github.com/kaspa-live/kaspa-graph-inspector/version"
	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/version"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

var zeroAddress = common.Address{}

type Account struct {
	address    common.Address
	privateKey *ecdsa.PrivateKey
	nonce      uint64
}

type MergeMining struct {
	config      *configPackage.Config
	database    *databasePackage.Database
	appConfig   *model.AppConfig
	account     Account
	ethClient   *ethclient.Client
	kaspaClient *rpcclient.RPCClient

	sync.Mutex
}

func NewMergeMining(config *configPackage.Config, database *databasePackage.Database) (*MergeMining, error) {
	appConfig := &model.AppConfig{
		ID:                true,
		KaspadVersion:     version.Version(),
		ProcessingVersion: versionPackage.Version(),
		Network:           config.ActiveNetParams.Name,
	}

	client, err := ethclient.Dial(config.CanxiumRpc)
	if err != nil {
		return nil, err
	}

	// Decode the private key from hex
	var privateKey *ecdsa.PrivateKey
	if len(config.PrivateKey) > 0 {
		privateKeyBytes, err := hex.DecodeString(config.PrivateKey)
		if err != nil {
			return nil, err
		}
		// Convert bytes to ECDSA private key
		key, err := crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, err
		}
		privateKey = key
	} else {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Criticalf("Failed to generate private key: %v", err)
		}
		privateKey = key
	}

	// Get the public key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}

	// Generate the address from the public key
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, err
	}

	if len(config.PrivateKey) <= 0 {
		privateKeyBytes := crypto.FromECDSA(privateKey)
		// Step 3: Convert the private key to a hexadecimal string
		privateKeyHex := common.Bytes2Hex(privateKeyBytes)
		account := &model.CanxiumAccount{
			Address:    address.String(),
			PrivateKey: privateKeyHex,
		}
		if err := database.InsertCanxiumAccount(account); err != nil {
			log.Criticalf("Failed to save account's private key: %v", err)
		}
	}

	log.Infof("Merge mining using account %s. Nonce %d", address.Hex(), nonce)
	rpcClient, err := rpcclient.NewRPCClient(config.KaspaRpc)
	if err != nil {
		logging.LogErrorAndExit("Could not connect to kaspa rpc: %s", err)
	}

	merge := &MergeMining{
		config:      config,
		database:    database,
		appConfig:   appConfig,
		ethClient:   client,
		kaspaClient: rpcClient,
		account: Account{
			address:    address,
			privateKey: privateKey,
			nonce:      nonce,
		},
	}

	return merge, nil
}

func (m *MergeMining) Start() error {
	for {
		mergeBlock, err := m.database.GetUnProcessMergeBlock()
		if err != nil {
			log.Tracef("Failed to query new merge block from database, sleep 3s, error: %s", err.Error())
			time.Sleep(3 * time.Second)
			continue
		}

		b, err := m.kaspaClient.GetBlock(mergeBlock.BlockHash, true)
		if err != nil || b.Error != nil {
			log.Errorf("Failed to get block info from kaspa node, error: %+v, block error: %+v", err, b.Error)
			time.Sleep(time.Second)
			continue
		}

		block, err := appmessage.RPCBlockToDomainBlock(b.Block)
		if err != nil {
			log.Errorf("Failed to convert rpc block to domain block, error: %+v", err)
			time.Sleep(time.Second)
			continue
		}

		if err := m.processBlock(block); err != nil {
			log.Errorf("Failed to process merge block, error: %+v", err)
			time.Sleep(time.Second)
			continue
		}
	}
}

// Submit and check transaction status
func (m *MergeMining) SubmitTransactions() error {
	for {
		mergeBlocks, err := m.database.GetPendingMergeBlocks()
		if err != nil {
			log.Tracef("Failed to query pending merge block from database, sleep 3s, error: %s", err.Error())
			time.Sleep(3 * time.Second)
			return err
			// continue
		}

		for _, block := range *mergeBlocks {
			rawTxBytes, err := hex.DecodeString(block.MergeTxRaw[2:])
			if err != nil {
				log.Errorf("Failed to decode raw transaction: %v", err)
				return err
			}

			var tx types.Transaction
			// Unmarshal the raw transaction using UnmarshalBinary
			err = tx.UnmarshalBinary(rawTxBytes)
			if err != nil {
				log.Errorf("Failed to unmarshal transaction: %v", err)
				return err
			}

			log.Infof("Sending transaction to canxium, hash %s, block hash %s, nonce: %d", tx.Hash(), tx.MergeProof().BlockHash(), tx.Nonce())
			err = m.ethClient.SendTransaction(context.Background(), &tx)
			if err != nil && err.Error() != "already known" && err.Error() != "nonce too low" {
				log.Warnf("Failed to send merge mining transaction %s to canxium network, error: %s", tx.Hash(), err.Error())
				return err
			}
		}

		i := 0
		for {
			if i >= len(*mergeBlocks) {
				break
			}
			block := (*mergeBlocks)[i]
			receipt, err := m.ethClient.TransactionReceipt(context.Background(), common.HexToHash(block.MergeTxHash))
			if err != nil && receipt == nil {
				log.Debugf("Failed to get transaction %s receipt: %s", block.MergeTxHash, err.Error())
				time.Sleep(time.Second)
				continue
			}

			log.Infof("Transaction %s success, status: %d, included in block %d", block.MergeTxHash, receipt.Status, receipt.BlockNumber.Int64())
			block.MergeTxSuccess = true
			err = m.database.InsertMergeBlock(&block)
			if err != nil {
				return errors.Wrapf(err, "Could not upsert block %s", block.BlockHash)
			}

			i++
		}

	}
}

func (p *MergeMining) processBlock(block *externalapi.DomainBlock) error {
	if len(block.Transactions) <= 0 {
		return nil
	}

	blockHash := consensushashing.BlockHash(block)
	log.Debugf("Processing block %s", blockHash)
	defer log.Debugf("Finished processing block %s", blockHash)

	databaseBlock := &model.MergeBlock{
		BlockHash:      blockHash.String(),
		Timestamp:      block.Header.TimeInMilliseconds(),
		IsValidBlock:   false,
		MergeTxSuccess: false,
	}

	signedTx, minerAddress, err := p.blockToMergeMiningTransaction(block)
	if err != nil && minerAddress != zeroAddress {
		return errors.Wrapf(err, "Could not build merge mining transaction for block %s, error: %+v, miner: %s", blockHash, err, minerAddress)
	}

	if err != nil && minerAddress == zeroAddress {
		databaseBlock.IsValidBlock = false
	} else if signedTx != nil {
		rawTx, err := signedTx.MarshalBinary()
		if err != nil {
			return errors.Errorf("Failed to marshal binary raw transaction error: %+v", err)
		}

		isExistSameBlock := p.database.IsExistSameBlockMinerAndTimeStamp(minerAddress.String(), databaseBlock.Timestamp)
		if isExistSameBlock {
			log.Warnf("Invalid block %s, same timestamp block existed in database: %d", databaseBlock.BlockHash, databaseBlock.Timestamp)
			databaseBlock.IsValidBlock = false
		} else {
			databaseBlock.Difficulty = signedTx.MergeProof().Difficulty().Uint64()
			if databaseBlock.Difficulty >= p.config.MinimumKaspaDifficulty {
				databaseBlock.IsValidBlock = true
				databaseBlock.MergeTxSigner = p.account.address.Hex()
				databaseBlock.MergeTxNonce = int64(p.account.nonce)
				databaseBlock.MergeTxRaw = "0x" + hex.EncodeToString(rawTx)
				databaseBlock.MergeTxHash = signedTx.Hash().Hex()
				databaseBlock.Miner = minerAddress.String()
			}
		}
	}

	err = p.database.InsertMergeBlock(databaseBlock)
	if err != nil {
		return errors.Wrapf(err, "Could not insert block %s", blockHash)
	}

	if databaseBlock.IsValidBlock {
		log.Infof("Inserted block %s to database, tx hash: %s, nonce: %d", blockHash, databaseBlock.MergeTxHash, databaseBlock.MergeTxNonce)
		p.account.nonce += 1
		// Send to canxium network
		if signedTx.Nonce() != 0 {
			err = p.ethClient.SendTransaction(context.Background(), signedTx)
			if err != nil {
				log.Warnf("Failed to send merge mining transaction to canxium network, error: %s", err.Error())
			}
		}
	}

	return nil
}

func (p *MergeMining) blockToMergeMiningTransaction(block *externalapi.DomainBlock) (*types.Transaction, common.Address, error) {
	blockHeader := types.NewImmutableKaspaBlockHeader(
		block.Header.Version(),
		block.Header.Parents(),
		block.Header.HashMerkleRoot(),
		block.Header.AcceptedIDMerkleRoot(),
		block.Header.UTXOCommitment(),
		block.Header.TimeInMilliseconds(),
		block.Header.Bits(),
		block.Header.Nonce(),
		block.Header.DAAScore(),
		block.Header.BlueScore(),
		block.Header.BlueWork(),
		block.Header.PruningPoint(),
	)

	proof := GenerateMerkleProofForCoinbase(block.Transactions)
	kaspaBock := &types.KaspaBlock{
		Header:      &blockHeader,
		MerkleProof: proof,
		Coinbase:    block.Transactions[0],
	}

	value := misc.MergeMiningReward(kaspaBock, p.config.HeliumForkTime, uint64(time.Now().Unix()))

	mineFnSignature := []byte("mergeMining(address)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(mineFnSignature)
	methodID := hash.Sum(nil)[:4]

	receiver, err := kaspaBock.GetMinerAddress()
	if err != nil {
		return nil, common.Address{}, err
	}
	var data []byte
	paddedAddress := common.LeftPadBytes(receiver.Bytes(), 32)
	data = append(data, methodID...)
	data = append(data, paddedAddress...)

	signedTx, err := types.SignTx(types.NewTx(&types.MergeMiningTx{
		ChainID:    big.NewInt(p.config.CanxiumChainId),
		Nonce:      p.account.nonce,
		GasTipCap:  big.NewInt(0),
		GasFeeCap:  big.NewInt(0),
		Gas:        100000,
		From:       p.account.address,
		To:         common.HexToAddress(p.config.MiningContract),
		Value:      value,
		Data:       data,
		Algorithm:  types.ScryptAlgorithm,
		MergeProof: kaspaBock,
	}), types.NewLondonSigner(big.NewInt(p.config.CanxiumChainId)), p.account.privateKey)
	if err != nil {
		return nil, common.Address{}, errors.Errorf("Failed to sign raw transaction error: %+v", err)
	}

	return signedTx, receiver, nil
}
