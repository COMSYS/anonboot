#!/usr/bin/python3
"""
This file generates a certain number of peers with valid
public/private key pairs and writes them into a file.
"""
import os
import pickle
from hashlib import sha256

import progressbar
from Cryptodome.Random.random import getrandbits

import protocol
import opreturn
import ipaddress
import random
from helpers import get_random_bytes, trans_to_string, generate_key_pair
from sys import argv


def generate_peers(num_peers: int) -> list:
    """Generate the given number of peers"""
    peer_list = []
    for _ in progressbar.progressbar(range(0, num_peers)):
        tx = sha256(getrandbits(256).to_bytes(32, 'big')).digest().hex()
        # We used a fixed tx value b/c it has no importance for the eval
        (pri, pub) = generate_key_pair()
        p = protocol.Peer(
            ip_address=ipaddress.IPv4Address(get_random_bytes(4)),
            port=int(random.randint(3000, 4000)),
            public_key=pub.to_string(),
            private_key=pri.to_string(),
            cont_tx=opreturn.Transaction(tx, 0),
            service=bytes([0x01, 0x00])
        )
        peer_list.append(p)
    return peer_list


def store_peers(peer_list: list):
    """Write the list of peers both to a csv file and to a pickle file."""
    num = len(peer_list)

    # create peer_dir folder if it does not exist
    my_path = '/'.join(
        os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
    peer_dir = my_path + "/../peers"  # Path to peer files
    # Create folder if it does not exist:
    try:
        os.mkdir(peer_dir)
    except FileExistsError:
        pass
    filename = "/peers_" + str(num) + ".pyc"
    csv = "/peers_" + str(num) + ".csv"
    with open(peer_dir + filename, 'wb') as fd:
        pickle.dump(peer_list,
                    fd)  # We also write a binary file to make usage simpler
    with open(peer_dir + csv, 'w') as fd:
        fd.write(
            "#;IP Address;Port;Public Key;Private Key;Cont_tx;Capabilities\n")
        for i in range(len(peer_list)):
            p = peer_list[i]
            fd.write("{};{};{};{};{};{};{}\n".format(
                i,
                p.ip_address,
                p.port,
                p.public_key.hex(),
                p.private_key.hex(),
                trans_to_string(p.cont_tx),
                p.capabilities.hex()
            ))
    print("Wrote keys to '" + peer_dir + filename + "'.")


if __name__ == '__main__':
    if len(argv) != 2:
        print("Usage: generate_peers.py NUM_PEERS")
    else:
        peers = generate_peers(int(argv[1]))
        store_peers(peers)
