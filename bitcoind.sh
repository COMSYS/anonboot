#!/bin/bash

# Starts the bitcoin deamon (server)
args=(${@})
if [ $# -lt 1 ]; then
    # Use default port
    OFFSET=0
else
    OFFSET=$1
    unset args[0]
fi


PORT=`expr 18443 + $OFFSET`
CONPORT=`expr 18000 + $OFFSET`
ROOT=$(dirname "$0")
ABSOLUTEROOT="$( cd "$(dirname "$0")" ; pwd -P )"
BITCOIND="$ROOT/bitcoin-0.17.1/bin/bitcoind"
ARGS="${args[@]}"
CONFFILE="../.bitcoin.conf"
DATADIR="$ABSOLUTEROOT/.data$OFFSET"
DEBUGARGS="-noconnect -checkpoints -checkmempool"

echo "**********************************"
echo "Bitcoin Deamon started on Port $PORT"
echo "**********************************"

mkdir -p $DATADIR
$BITCOIND -conf=$CONFFILE -datadir="$DATADIR" -port=$CONPORT -rpcport=$PORT $DEBUGARGS $ARGS
