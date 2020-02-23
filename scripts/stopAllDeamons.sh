#!/usr/bin/env bash
# Stops all running deamons
for i in 0 1 2 3 4 5 6; do ./bitcoin-cli.sh $i stop;  done
