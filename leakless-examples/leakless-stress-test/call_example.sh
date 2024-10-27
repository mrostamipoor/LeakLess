#!/bin/bash


URL="http://0.0.0.0:3001/stress-test"
PARAMETERS='{"variable1": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS","variable2": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS", "variable3": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS", "variable4": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS", "variable5": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS","variable6": "LEAKLESS_rz7UXVKil4pkduIbt4IJyVbPnscTT6cpSqBkIhdYWZco2rjn7lxcTaHuBssE_LEAKLESS"}'


# Running curl command
curl  "$URL" -d "$PARAMETERS"
