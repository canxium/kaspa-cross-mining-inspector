#!/bin/bash

set -e
# Build processing
docker build -f processing/Dockerfile -t kaspa-merge-mining:latest processing