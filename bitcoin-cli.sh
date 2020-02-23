#!/bin/bash

args=(${@})
if [ $# -lt 1 ] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
    # Use default port
    OFFSET=0
else
    OFFSET=$1
    unset args[0]
fi


PORT=`expr 18443 + $OFFSET`

ROOT=$(dirname "$0")
ABSOLUTEROOT="$( cd "$(dirname "$0")" ; pwd -P )"
BITCOINCLI="$ROOT/bitcoin-0.17.1/bin/bitcoin-cli"
ARGS="${args[@]}"
CONFFILE="../.bitcoin.conf"
DATADIR="$ABSOLUTEROOT/.data$OFFSET"

$BITCOINCLI -conf=$CONFFILE -datadir="$DATADIR" -rpcport=$PORT $ARGS

