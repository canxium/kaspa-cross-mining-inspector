package main

import (
	"fmt"

	databasePackage "github.com/kaspa-live/kaspa-graph-inspector/database"
	configPackage "github.com/kaspa-live/kaspa-graph-inspector/infrastructure/config"
	"github.com/kaspa-live/kaspa-graph-inspector/infrastructure/logging"
	processingPackage "github.com/kaspa-live/kaspa-graph-inspector/processing"
	versionPackage "github.com/kaspa-live/kaspa-graph-inspector/version"
	"github.com/kaspanet/kaspad/version"
)

func main() {
	fmt.Println("=================================================")
	fmt.Println("Kaspa Merge Mining (KGI)   -   Processing Tier")
	fmt.Println("=================================================")

	config, err := configPackage.LoadConfig()
	if err != nil {
		logging.LogErrorAndExit("Could not parse command line arguments.\n%s", err)
	}

	logging.Logger().Infof("Application version %s", versionPackage.Version())
	logging.Logger().Infof("Embedded kaspad version %s", version.Version())
	logging.Logger().Infof("Network %s", config.ActiveNetParams.Name)
	logging.Logger().Infof("Helium Fork %d", config.HeliumForkTime)
	logging.Logger().Infof("Mining Contract %s", config.MiningContract)
	logging.Logger().Infof("Min Difficulty %d", config.MinimumKaspaDifficulty)

	database, err := databasePackage.Connect(config.DatabaseConnectionString)
	if err != nil {
		logging.LogErrorAndExit("Could not connect to database %s: %s", config.DatabaseConnectionString, err)
	}
	defer database.Close()

	logging.Logger().Infof("Connected to database %s", config.DatabaseConnectionString)
	processing, err := processingPackage.NewMergeMining(config, database)
	if err != nil {
		logging.LogErrorAndExit("Could not initialize processing: %s", err)
	}

	logging.Logger().Infof("Processing initialized")
	processing.SubmitTransactions()
	if err != nil {
		logging.LogErrorAndExit("Could not start kaspad: %s", err)
	}

	<-make(chan struct{})
}
