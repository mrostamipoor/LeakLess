#!/bin/bash


URL="http://0.0.0.0:3001/stored-password"
PARAMETERS=''


# Running curl command
curl  "$URL" -d "$PARAMETERS"
