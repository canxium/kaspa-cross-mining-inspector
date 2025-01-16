#!/bin/bash

set -e
# Build processing
docker build -f Dockerfile -t kaspa-merge-mining:latest ./