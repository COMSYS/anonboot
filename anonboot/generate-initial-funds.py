#!/usr/bin/python3

"""
This script generates blocks and gives the money to newly created
addresses which are stored in a file. Necessary before working with demo.py.
"""
import ipaddress
import os
import pickle
import random
import sys

import protocol
from protocol import State
from bitcoinrpc.authproxy import AuthServiceProxy
import opreturn
from helpers import get_random_bytes, generate_key_pair

# CONSTANTS
NUM_PEERS = 100  # peer accounts to initialize
NUM_USERS = 100  # users to initialize

port = "18443"
if len(sys.argv) > 1:
    port = sys.argv[1]

# create bin folder if it does not exist
my_path = '/'.join(
    os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
working_dir = my_path + "/../state"  # Path to binary files
# Create bin folder if it does not exist:
try:
    os.mkdir(working_dir)
except FileExistsError:
    pass

# Connect to Deamon
con = AuthServiceProxy(
    "http://%s:%s@127.0.0.1:%s" % (State.RPC_USER, State.RPC_PASSWORD, port))

peers = []  # List of peers, each with valid credit
users = []  # List of users, each with valid credit

for i in range(0, NUM_PEERS + 1):
    b = con.generate(1)
    tx = con.getblock(b[0])['tx'][0]
    (pri, pub) = generate_key_pair()
    p = protocol.Peer(
        ip_address=ipaddress.IPv4Address(get_random_bytes(4)),
        port=int(random.randint(3000, 4000)),
        public_key=pub.to_string(),
        private_key=pri.to_string(),
        cont_tx=opreturn.Transaction(tx, 0),
        service=bytes([0x01, 0x00])
    )
    peers.append(p)

for i in range(0, NUM_USERS + 1):
    b = con.generate(1)
    tx = con.getblock(b[0])['tx'][0]
    users.append({'txs': [opreturn.Transaction(tx, 0)]})

# Generate another 100 blocks to make all coins spendable
con.generate(100)

# Store address list to file
with open(working_dir + "/peers.pyc", 'wb') as fd:
    pickle.dump(peers, fd)
with open(working_dir + "/users.pyc", 'wb') as fd:
    pickle.dump(users, fd)
