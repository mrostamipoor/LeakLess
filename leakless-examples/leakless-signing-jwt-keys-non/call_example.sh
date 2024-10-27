#!/bin/bash


URL="http://0.0.0.0:3000/jwt-sign"
PARAMETERS='{"ancestorId":"1e0c644c-0caf-40b6-9fa3-8107ff6a82ed", "query":"value2", "limit":"20"}'


# Running curl command
curl  -X POST -d "$PARAMETERS" -H "Content-Type: application/json" "$URL" 
