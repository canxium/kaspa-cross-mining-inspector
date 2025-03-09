package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/kaspa-live/kaspa-graph-inspector/infrastructure/logging"
	versionPackage "github.com/kaspa-live/kaspa-graph-inspector/version"
	kaspaConfigPackage "github.com/kaspanet/kaspad/infrastructure/config"
	kaspaLogger "github.com/kaspanet/kaspad/infrastructure/logger"
	"github.com/kaspanet/kaspad/util"
	"github.com/kaspanet/kaspad/version"
	"github.com/pkg/errors"
)

const (
	appDataDirectory      = "kgi-processing"
	defaultLogDirname     = "logs"
	defaultLogLevel       = "info"
	defaultLogFilename    = "kgi-processing.log"
	defaultErrLogFilename = "kgi-processing_err.log"

	CrescendoActivation = math.MaxUint64
)

var (
	// DefaultAppDir is the default home directory for kaspad.
	DefaultAppDir          = util.AppDir(appDataDirectory, false)
	defaultDataDir         = filepath.Join(DefaultAppDir)
	MinimumKaspaDifficulty = uint64(100000)
	CanxiumChainId         = int64(3003)
	DelayInMilliSecond     = int64(3000)
)

type Flags struct {
	ShowVersion              bool     `short:"V" long:"version" description:"Display version information and exit"`
	AppDir                   string   `short:"b" long:"appdir" description:"Directory to store data"`
	LogDir                   string   `long:"logdir" description:"Directory to log output."`
	DatabaseConnectionString string   `long:"connection-string" description:"Connection string for PostgrSQL database to connect to. Should be of the form: postgres://<username>:<password>@<host>:<port>/<database name>"`
	ConnectPeers             []string `long:"connect" description:"Connect only to the specified peers at startup"`
	DNSSeed                  string   `long:"dnsseed" description:"Override DNS seeds with specified hostname (Only 1 hostname allowed)"`
	GRPCSeed                 string   `long:"grpcseed" description:"Hostname of gRPC server for seeding peers"`
	Resync                   bool     `long:"resync" description:"Force to resync all available node blocks with the PostgrSQL database -- Use if some recently added blocks have missing parents"`
	ClearDB                  bool     `long:"clear-db" description:"Clear the PostgrSQL database and sync from scratch"`
	LogLevel                 string   `short:"d" long:"loglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	PrivateKey             string `long:"private-key" description:"Private key of the account to submit merge mining transaction"`
	CanxiumRpc             string `long:"canxium-rpc" description:"Canxium RPC endpoint"`
	KaspaRpc               string `long:"kaspa-rpc" description:"Kaspa RPC endpoint"`
	HeliumForkTime         uint64 `long:"canxium-helium-time" description:"Canxium Helium fork time"`
	MiningContract         string `long:"mining-contract" description:"Canxium merge mining contract"`
	MinimumKaspaDifficulty uint64 `long:"min-diff" description:"Canxium merge mining min diff"`
	CanxiumChainId         int64  `long:"canxium-chainid" description:"Canxium chain Id"`
	MinerAddress           string `long:"miner-address" description:"Canxium miner address to filter the block"`

	CrescendoActivation uint64 `long:"crescendo-activation" description:"Kaspa crescendo activation"`
	DelayInMilliSecond  int64  `long:"delay-millisecond" description:"How many millisecond this program will delay before process the block"`
	AlwaysBlock         bool   `long:"always-block" description:"Always block all block of the black list miner"`

	kaspaConfigPackage.NetworkFlags
}

// MinerRateConfig holds the rate limit configuration for miners
type MinerRateConfig struct {
	RateLimits map[string]int  // Miner address -> Rate limit number
	GoodMiners map[string]bool // Miner address -> Is good behavior
}

// ShouldProcessBlock checks if a block should be processed for a given miner
func (m *MinerRateConfig) ShouldProcessBlock(minerAddress string, totalBlocks int) bool {
	address := strings.ToLower(minerAddress)
	rateLimit, exists := m.RateLimits[address]
	if !exists {
		return true // No rate limit set for this miner
	}

	if m.GoodMiners[address] {
		// Good behavior: Drop 1 every n blocks
		return totalBlocks%rateLimit != 0
	}

	// Normal behavior: Process 1 every n blocks
	return totalBlocks%rateLimit == 0
}

type Config struct {
	*Flags

	RateLimit MinerRateConfig
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(DefaultAppDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but they variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

func defaultFlags() *Flags {
	return &Flags{
		AppDir:                 defaultDataDir,
		LogLevel:               defaultLogLevel,
		MinimumKaspaDifficulty: MinimumKaspaDifficulty,
		CanxiumChainId:         CanxiumChainId,
		CrescendoActivation:    CrescendoActivation,
		DelayInMilliSecond:     DelayInMilliSecond,
	}
}

func LoadConfig() (*Config, error) {
	funcName := "loadConfig"
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)

	cfgFlags := defaultFlags()
	parser := flags.NewParser(cfgFlags, flags.HelpFlag)
	_, err := parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if ok := errors.As(err, &flagsErr); !ok || flagsErr.Type != flags.ErrHelp {
			return nil, errors.Wrapf(err, "Error parsing command line arguments: %s\n\n%s", err, usageMessage)
		}
		return nil, err
	}
	cfg := &Config{
		Flags: cfgFlags,
	}

	// Show the version and exit if the version flag was specified.
	if cfg.ShowVersion {
		fmt.Println(appName, "version", versionPackage.Version())
		fmt.Println("kaspad version", version.Version())
		os.Exit(0)
	}

	if cfg.DatabaseConnectionString == "" {
		return nil, errors.Errorf("--connection-string is required.")
	}

	if cfg.CanxiumRpc == "" {
		return nil, errors.Errorf("--canxium-rpc is required.")
	}

	err = cfg.ResolveNetwork(parser)
	if err != nil {
		return nil, err
	}

	cfg.AppDir = cleanAndExpandPath(cfg.AppDir)
	// Append the network type to the app directory so it is "namespaced"
	// per network.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.AppDir = filepath.Join(cfg.AppDir, cfg.NetParams().Name)

	// Logs directory is usually under the home directory, unless otherwise specified
	if cfg.LogDir == "" {
		cfg.LogDir = filepath.Join(cfg.AppDir, defaultLogDirname)
	}
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)

	// Special show command to list supported subsystems and exit.
	if cfg.LogLevel == "show" {
		fmt.Println("Supported subsystems", kaspaLogger.SupportedSubsystems())
		os.Exit(0)
	}

	// Initialize log rotation. After log rotation has been initialized, the
	// logger variables may be used.
	logging.InitLog(filepath.Join(cfg.LogDir, defaultLogFilename), filepath.Join(cfg.LogDir, defaultErrLogFilename))

	// Parse, validate, and set debug log level(s).
	if err := kaspaLogger.ParseAndSetLogLevels(cfg.LogLevel); err != nil {
		err := errors.Errorf("%s: %s", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, err
	}

	// rate limit
	limit := MinerRateConfig{
		RateLimits: map[string]int{
			"0x1f11fe5f07d1e74c8f77a3cb3101438878853e12": 6,  // drop 1 every n block, F2Pool
			"0x1923a3a063c1964b3a3cb243527f125e702ac5f1": 5,  // drop 1 every n block, WhalePool
			"0x92d003f6ba388df9943c01a26a9616b9bda0ac7b": 8,  // drop 1 every n block, k1Pool
			"0x61faba23a639d1028e74bffe14c483bb80be9d0e": 6,  // process 1 in every n blocks, HumPool
			"0x0bd3df983e80048c6a2e388fc173436c55c0190b": 5,  // process 1 in every n blocks, AntPool
			"0x9f43cfea05ab3a39951000d4a85b7f0ca4e23105": 15, // process 1 every n blocks, Kryptex

		},
		GoodMiners: map[string]bool{
			"0x1f11fe5f07d1e74c8f77a3cb3101438878853e12": true, // Miner2 has good behavior, drop 1 every n block
			"0x1923a3a063c1964b3a3cb243527f125e702ac5f1": true,
			"0x92d003f6ba388df9943c01a26a9616b9bda0ac7b": true,
		},
	}

	cfg.RateLimit = limit

	return cfg, nil
}
