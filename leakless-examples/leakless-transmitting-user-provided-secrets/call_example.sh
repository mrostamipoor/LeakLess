#!/bin/bash


URL="http://0.0.0.0:3001/transfer-secret"
PARAMETERS='{"ancestorId":"1e0c644c-0caf-40b6-9fa3-8107ff6a82ed", "query":"value2", "limit":"20","additionalText":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat!"}'
HEADERS=(-H 'UNKEY-KEY: ab12cd34ef56gh78ij90klmnopqr23stuv45wxyz')

# Running curl command
curl "${HEADERS[@]}" "$URL" -d "$PARAMETERS"
