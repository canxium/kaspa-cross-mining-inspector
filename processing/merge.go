package processing

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/txpool"
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

const (
	// prefix of kaspa miner in the coinbase transaction payload. To extract the canxium address
	minerTagPrefix = "canxiuminer:"
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
			mergeBlock.IsValidBlock = false
			if err := m.database.InsertMergeBlock(mergeBlock); err != nil {
				return errors.Wrapf(err, "Could not insert block %s", mergeBlock.BlockHash)
			}

			log.Errorf("Failed to get block info from kaspa node, error: %+v, block error: %+v", err, b)
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
			receipt, err := m.ethClient.TransactionReceipt(context.Background(), common.HexToHash(block.MergeTxHash))
			if err == nil && receipt != nil {
				log.Infof("Transaction %s success, status: %d, included in block %d", block.MergeTxHash, receipt.Status, receipt.BlockNumber.Int64())
				block.MergeTxSuccess = true
				err = m.database.InsertMergeBlock(&block)
				if err != nil {
					return errors.Wrapf(err, "Could not upsert block %s", block.BlockHash)
				}
				continue
			}

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

			log.Debugf("Sending transaction to canxium, hash %s, block hash %s, nonce: %d", tx.Hash(), tx.AuxPoW().BlockHash(), tx.Nonce())
			err = m.ethClient.SendTransaction(context.Background(), &tx)
			if err != nil && err.Error() != txpool.ErrAlreadyKnown.Error() {
				// handle common error, and drop all tx belone to this signer, then restart to generate another signer
				log.Debugf("Failed to send merge mining transaction %s to canxium network, droping, error: %s", tx.Hash(), err.Error())
				block.IsValidBlock = false
				if dbErr := m.database.InsertMergeBlock(&block); dbErr != nil {
					return errors.Wrapf(err, "Could not insert block %s", block.BlockHash)
				}
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func (p *MergeMining) processBlock(block *externalapi.DomainBlock) error {
	blockHash := consensushashing.BlockHash(block)
	log.Debugf("Processing block %s", blockHash)
	defer log.Debugf("Finished processing block %s", blockHash)
	databaseBlock := &model.MergeBlock{
		BlockHash:      blockHash.String(),
		Timestamp:      block.Header.TimeInMilliseconds(),
		IsValidBlock:   false,
		MergeTxSuccess: false,
	}

	if len(block.Transactions) > 0 && p.isValidCrossMiningBlock(block) {
		signedTx, minerAddress, err := p.blockToMergeMiningTransaction(block)
		if err != nil && minerAddress != zeroAddress {
			return errors.Wrapf(err, "Could not build merge mining transaction for block %s, error: %+v, miner: %s", blockHash, err, minerAddress)
		}

		if !strings.EqualFold(minerAddress.String(), p.config.MinerAddress) {
			databaseBlock.IsValidBlock = false
		} else {
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
					databaseBlock.Difficulty = signedTx.AuxPoW().Difficulty().Uint64()
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
		}

		if databaseBlock.IsValidBlock {
			log.Infof("Inserted block %s to database, tx hash: %s, nonce: %d", blockHash, databaseBlock.MergeTxHash, databaseBlock.MergeTxNonce)
			// Send to canxium network
			err = p.ethClient.SendTransaction(context.Background(), signedTx)
			if err == nil {
				log.Infof("Sent transaction to canxium success, hash %s, nonce: %d", databaseBlock.MergeTxHash, databaseBlock.MergeTxNonce)
				p.account.nonce += 1
			} else {
				log.Warnf("Failed to send tx %s | block hash %s to canxium network, error: %s", databaseBlock.MergeTxHash, blockHash, err.Error())
				// This kaspa block aready sent to canxium, have to skip it and not increase the nonce
				// Check to see if the error is the block itself, then skip this block
				if err.Error() == txpool.ErrMergeTxAlreadyKnown.Error() || strings.Contains(err.Error(), "invalid merge mining transaction:") {
					databaseBlock.IsValidBlock = false
				} else {
					return err
				}
			}
		}
	}

	err := p.database.InsertMergeBlock(databaseBlock)
	if err != nil {
		return errors.Wrapf(err, "Could not insert block %s", blockHash)
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

	proof := GenerateMerkleProofForCoinbase(block.Transactions, p.config.StorageMassActivated)
	kaspaBock := &types.KaspaBlock{
		Header:               &blockHeader,
		MerkleProof:          proof,
		Coinbase:             block.Transactions[0],
		StorageMassActivated: p.config.StorageMassActivated,
	}

	value := misc.CrossMiningReward(kaspaBock, p.config.HeliumForkTime, uint64(time.Now().Unix()))

	mineFnSignature := []byte("crossChainMining(address,uint16,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(mineFnSignature)
	methodID := hash.Sum(nil)[:4]

	receiver, err := kaspaBock.GetMinerAddress()
	if err != nil {
		return nil, common.Address{}, err
	}
	paddedAddress := common.LeftPadBytes(receiver.Bytes(), 32)
	timestamp := big.NewInt(block.Header.TimeInMilliseconds()) // Replace with the actual timestamp
	chain := types.KaspaChain
	// Convert the chain ID to a hexadecimal value and pad it to 32 bytes
	chainHex := fmt.Sprintf("%04x", chain)                             // Convert uint16 to a 4-character hex string
	chainPadded, _ := hex.DecodeString(fmt.Sprintf("%064s", chainHex)) // Pad with leading zeros to 32 bytes

	// Timestamp (uint256) is padded to 32 bytes
	timestampPadded := make([]byte, 32)
	timestamp.FillBytes(timestampPadded)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, chainPadded...)
	data = append(data, timestampPadded...)

	signedTx, err := types.SignTx(types.NewTx(&types.CrossMiningTx{
		ChainID:   big.NewInt(p.config.CanxiumChainId),
		Nonce:     p.account.nonce,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(0),
		Gas:       100000,
		From:      p.account.address,
		To:        common.HexToAddress(p.config.MiningContract),
		Value:     value,
		Data:      data,
		AuxPoW:    kaspaBock,
	}), types.NewLondonSigner(big.NewInt(p.config.CanxiumChainId)), p.account.privateKey)
	if err != nil {
		return nil, common.Address{}, errors.Errorf("Failed to sign raw transaction error: %+v", err)
	}

	return signedTx, receiver, nil
}

func (m *MergeMining) isValidCrossMiningBlock(block *externalapi.DomainBlock) bool {
	if len(block.Transactions) <= 0 {
		return false
	}

	payload := block.Transactions[0].Payload
	tagLength := len(minerTagPrefix) + 40 // 40 characters for the address
	if len(payload) < tagLength {
		// Payload is too short to contain a valid tag
		return false
	}

	// Extract the last part of the payload
	tag := string(payload[len(payload)-tagLength:])

	// Validate the prefix
	return strings.HasPrefix(tag, minerTagPrefix)
}
