#!/usr/bin/env bash

# This was used to determine the maximal number of TXs that can be written into a block.
DIR=$(dirname "$0")
ROOT="$DIR/.."
DATADIR="$ROOT/.data"
SESSION="Test-Blocksize"
tmux -2 new-session -d -s $SESSION
tmux select-window -t $SESSION:0
tmux select-pane -t 0
tmux send-keys "$ROOT/bitcoin-cli.sh stop || true" C-m
sleep 1s
tmux send-keys "rm -rf $DATADIR" C-m
sleep 1s
tmux send-keys "$ROOT/bitcoind.sh" C-m
sleep 5s
tmux split-window -h
tmux select-pane -t 1
tmux send-keys "time python3 $ROOT/anonboot/blocksize_test.py" C-m
