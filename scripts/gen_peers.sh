#!/usr/bin/env bash
# Generate Peer Files for all required sizes
echo "Generate peer files for 500 1000 5000 10000 50000 10000 peers!"
for PEERS in 500 1000 5000 10000 50000 10000 ; do
    python3 anonboot/generate_peers.py $PEERS
done
