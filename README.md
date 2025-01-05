kaspa-merge-mining
=====================

This is a kaspad launcher to sync and filter out valid blocks with the merge mining program, then initiate the merge transaction and send it to the Canxium network

* The `processing` node connects to the Kaspa network the same way a regular kaspad node does and starts syncing just as a kaspad node would
* While it's syncing, it writes metadata about every block to the postgres database included the merge mining transaction.

Development
-----------

For development, it's recommended to run KGI from within Docker

1. Make sure you have docker installed by running `docker --version`
2. Make sure you have docker-compose installed by running `docker-compose --version`
3. Define the following environment variables:
   1. POSTGRES_USER=username
   2. POSTGRES_PASSWORD=password
   3. POSTGRES_DB=database-name
   8. KASPAD_VERSION=4a560f25a60e876b58d2643ca6eb7e07525e76cc (this can be either a specific kaspda commit hash or a kaspad tag)

4. Run: `docker compose -f docker-compose.yaml up -d`