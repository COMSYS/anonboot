#!/usr/bin/python3
"""
This module contains the eval code that measures # peers
in a randomly chosen network given a certain number of
malicious peers.
"""
import math
import sys
from hashlib import sha256

from Cryptodome.Random.random import getrandbits
from progressbar import progressbar

from eval import get_peers, get_security_eval_path, get_timestamp
from parser.security import security_parser
from protocol import _compute_network_seed, _sample


def get_filename(num_peers, user_size, min_mal, max_mal, min_peer,
                 max_peer, reps, ending=".csv") -> str:
    """Return the corresponding filename for the given parameters"""
    if min_mal == max_mal:
        mal_int = str(min_mal)
    else:
        mal_int = "{}to{}".format(
            min_mal,
            max_mal
        )
    if min_peer == max_peer:
        peer_int = str(min_peer)
    else:
        peer_int = "{}to{}".format(min_peer, max_peer)

    filename = "{}_security_{}peers_{}users_{}mal_{}mixnet_{}reps{}".format(
        get_timestamp(),
        num_peers,
        user_size,
        mal_int,
        peer_int,
        reps,
        ending
    )
    return filename


if __name__ == '__main__':

    args = security_parser.parse_args()

    NUM_PEERS = args.peers if args.peers is not None else 10000  # total
    # number of peers

    MIN_PERCENT_MALICIOUS = args.malicious[0]
    MAX_PERCENT_MALICIOUS = args.malicious[1]
    STEP_PERCENT_MALICIOUS = args.malicious[2]
    # Percentage of above peers that are malicious

    USER_SIZE = args.user_size if args.user_size is not None else 100  #
    # Number of users in the generated networks

    MIN_PEER_SIZE = args.peer_size[0]
    MAX_PEER_SIZE = args.peer_size[1]
    STEP_PEER_SIZE = args.peer_size[2]
    # Peer size of the generated NWs

    REPEAT = args.reps if args.reps is not None else 10000
    # How many repeats per configuration

    # we use a fixed protocol for the evaluation
    PROTOCOL = bytes([0x01])

    # Load peers
    try:
        peers = get_peers(NUM_PEERS)
    except FileNotFoundError:
        print("File peers/peers_%d.pyc does not exist. Execute " % NUM_PEERS +
              "'anonboot/generate_peers.py %d'." % NUM_PEERS)
        sys.exit()

    eval_dir = get_security_eval_path()

    # Generate file name for measurement
    res_file = eval_dir + '/' + get_filename(NUM_PEERS, USER_SIZE,
                                             MIN_PERCENT_MALICIOUS,
                                             MAX_PERCENT_MALICIOUS,
                                             MIN_PEER_SIZE, MAX_PEER_SIZE,
                                             REPEAT)

    with open(res_file, 'w') as fd:
        # Write Header --------------------------------------------------------
        if MIN_PERCENT_MALICIOUS == MAX_PERCENT_MALICIOUS:
            percentage_text = "Constant at %d" % MIN_PERCENT_MALICIOUS
        else:
            percentage_text = "From {} To {} Step {}".format(
                MIN_PERCENT_MALICIOUS,
                MAX_PERCENT_MALICIOUS,
                STEP_PERCENT_MALICIOUS
            )
        if MIN_PEER_SIZE == MAX_PEER_SIZE:
            mixnet_text = "Constant at %d" % MIN_PEER_SIZE
        else:
            mixnet_text = "From {} To {} Step {}".format(
                MIN_PEER_SIZE,
                MAX_PEER_SIZE,
                STEP_PEER_SIZE
            )
        fd.write("------------------------HEADER------------------------\n")
        fd.write("Peer Number: {}\n".format(NUM_PEERS))
        fd.write("User per Network/ User Size: {}\n".format(USER_SIZE))
        fd.write("Mixnet Size: {}\n".format(mixnet_text))
        fd.write("Percentage Malicious Peers: {}\n".format(percentage_text))
        fd.write("Repetitions per config: {}\n".format(REPEAT))
        fd.write(
            "Peers from file: {}\n".format("peers/peers_%d.csv" % NUM_PEERS))
        fd.write(
            "# Malicious Peers TOTAL;Peers per Network;Repetion No;# "
            "Malicious Peers in sampled NW\n")
        fd.write("----------------------END-HEADER----------------------\n")

    for mal in range(MIN_PERCENT_MALICIOUS, MAX_PERCENT_MALICIOUS + 1, STEP_PERCENT_MALICIOUS):
        if MIN_PERCENT_MALICIOUS == 33:
            # Special case: 1/3
            num_mal_peers = math.floor(NUM_PEERS / 3.)
        else:
            num_mal_peers = math.ceil(mal * NUM_PEERS / 100.)
        # We just assume that the first num_mal_peers of the peer list
        # are malicious
        for ps in progressbar(range(MIN_PEER_SIZE, MAX_PEER_SIZE + 1, STEP_PEER_SIZE)):
            for r in range(REPEAT):
                merkle = sha256(getrandbits(256).to_bytes(32, 'big')).digest().hex()
                seed = _compute_network_seed(PROTOCOL, ps, USER_SIZE, merkle)  # We use a random merkle root
                res = _sample(seed, peers, ps)
                num_malicious = 0
                for p in range(0, num_mal_peers):
                    if peers[p] in res:
                        num_malicious += 1
                with open(res_file, 'a') as fd:
                    fd.write('{};{};{};{}\n'.format(num_mal_peers, ps, r, num_malicious))
