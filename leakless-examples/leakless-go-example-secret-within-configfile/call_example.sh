#!/bin/bash


URL="http://0.0.0.0:3001/"
PARAMETERS=""
HEADERS=(-H 'api-key: LEAKLESS_secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_LEAKLESS')

# Running curl command
curl "${HEADERS[@]}" "$URL" -d "$PARAMETERS"
