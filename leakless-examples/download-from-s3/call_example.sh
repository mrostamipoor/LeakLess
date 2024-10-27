#!/bin/bash


URL="http://0.0.0.0:3001/download-from-s3"
PARAMETERS=""

# Running curl command
curl "$URL" -d "$PARAMETERS"
