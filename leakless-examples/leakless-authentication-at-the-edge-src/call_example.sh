#!/bin/bash

URL="http://0.0.0.0:3001/authenticate-at-edge-enc"
NOTION_KEY="LEAKLESS_secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_LEAKLESS"

curl -i "$URL" -H "Notion-key: $NOTION_KEY"