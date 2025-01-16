kaspa-merge-mining
=====================

This is a kaspad launcher to sync and filter out valid blocks with the merge mining program, then initiate the merge transaction and send it to the Canxium network

Launcher 1:
* The `cmd/kaspad/main.go` node connects to the Kaspa network the same way a regular kaspad node does and starts syncing just as a kaspad node would
* While it's syncing, it writes metadata about every block to the postgres database included the merge mining transaction.
* This launcher is good for mainnet, however, it is depend on the kaspad, which is deprecated

Launcher 2:
* The `cmd/rpc/main.go` connect to postgres database and get the block hash and timestamp, then connect to a kaspa rpc to get block info and create the merge transaction. This launcher needs another kaspa node to sync and write block hash to database.
* You have to setup a custom kaspad node to synce and write the block metadata to database first.

Development
-----------

For development, it's recommended to run from within Docker

1. Make sure you have docker installed by running `docker --version`
2. Make sure you have docker-compose installed by running `docker-compose --version`
3. Define the following environment variables:
   1. POSTGRES_USER=username
   2. POSTGRES_PASSWORD=password
   3. POSTGRES_DB=database-name

4. Run: `docker compose -f docker-compose.yaml up -d`