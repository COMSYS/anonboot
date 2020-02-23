#!/bin/bash

args=(${@})
if [ $# -lt 1 ] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
    # Use default port
    OFFSET=0
else
    OFFSET=$1
    unset args[0]
fi

ROOT=$(dirname "$0")
DATADIR="$ROOT/.data$OFFSET"
PORT=`expr 18443 + $OFFSET`

# Stop bitcoind, don't care if it does not already run
$ROOT/bitcoin-cli.sh $OFFSET stop || true

sleep 1s

# Remove old regtest dir
echo "...Removing $DATADIR/regtest"
rm -rf $DATADIR/regtest

sleep 1s

# Start bitcoind again
$ROOT/bitcoind.sh $OFFSET> "deamon$OFFSET.log"&

sleep 5s

# Generate 101 blocks for funds
python3 $ROOT/anonboot/generate-initial-funds.py $PORT

# Stop bitcoind again
$ROOT/bitcoin-cli.sh $OFFSET stop
