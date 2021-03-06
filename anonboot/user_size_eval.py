#!/usr/bin/python3
"""
This module contains the eval code that evaluates how
many blocks are necessary to contain all user requests for
a given percentage of space that is allowed to be used
by peer ads.
"""
import statistics
import sys

from Cryptodome.Random.random import randint
from bitcoinrpc.authproxy import AuthServiceProxy
from progressbar import progressbar

import config
from config import EMPTY_BLOCK_SIZE
from eval import get_user_size_eval_path, generate_valid_source_tx, \
    get_timestamp
from pow import NONCE_LENGTH
from helpers import get_random_bytes
from parser.user_size import user_size_parser
from protocol import State, User


def get_filename(ad_range: tuple, reps: int, ending: str = '.csv') -> str:
    """Return filename for user_size eval file"""
    range_str = "{}to{}step{}".format(
        *ad_range
    )

    return "{}_userReq_{}_{}reps{}".format(
        get_timestamp(),
        range_str,
        reps,
        ending
    )


if __name__ == '__main__':
    if not config.EVAL:
        print("The value config.EVAL has to be set to True for this Eval!")
        sys.exit()

    args = user_size_parser.parse_args()
    # Min, max and step define the range for the while loop
    MIN = args.MIN
    MAX = args.MAX
    STEP = args.STEP
    PORT = args.port if args.port is not None else 18443
    State.PORT = PORT
    REPS = args.reps if args.reps is not None else 100  # Number of
    # repetitions per config

    SERVICE = bytes([0x01, 0x00])  # Service ID used for ads

    # Connect to Daemon
    con = AuthServiceProxy(
        "http://%s:%s@127.0.0.1:%s" % (
            State.RPC_USER,
            State.RPC_PASSWORD,
            PORT
        )
    )
    # Create state in which each block can contain advertisements.
    s = State(1, 1, 0)

    # Define a list of tx to take the money from
    generate_valid_source_tx(s, con, MAX)

    # Determine size of coinbase TXs
    # Re-Connect to Daemon (to avoid overburdening bitcoind)
    con = AuthServiceProxy(
        "http://%s:%s@127.0.0.1:%s" % (
            State.RPC_USER,
            State.RPC_PASSWORD,
            PORT
        )
    )
    con.generate(1)
    bh = con.getblockhash(con.getblockcount())
    json = con.getblock(bh, 2)
    coinbase_sizes = [183]
    coinbase_avg_sizes = [156]
    for tx in json['tx']:
        coinbase_sizes.append(tx['size'])
        coinbase_avg_sizes.append(tx['vsize'])
    print("Coinbase transactions have sizes {} and stripped sizes {}.".format(
        coinbase_sizes, coinbase_avg_sizes))

    filename = get_filename((MIN, MAX, STEP), REPS)
    file_path = get_user_size_eval_path() + '/' + filename
    error_count = 0

    with open(file_path, 'w') as fd:
        fd.write("------------------------HEADER------------------------\n")
        fd.write("Number of User Requests, (from, to, step): {}\n".format(
            str((MIN, MAX, STEP))))
        fd.write("Repetitions per config: {}\n".format(REPS))
        fd.write(
            "Number of Requests; Repetition; Size of Block (bytes);Stripped "
            "Size of Block (Bytes); Block Weight; "
            "AVG Transaction Size; AVG Virtual Transaction Size; Transaction "
            "Sizes; Virtual Transaction Sizes\n")
        fd.write("----------------------END-HEADER----------------------\n")
    # 1: BLOCK SIZE by NUMBER of User Requests
    for n in progressbar(range(MIN, MAX + 1, STEP)):
        for r in range(0, REPS):
            completed = False
            while not completed:
                # The connection breaks after some time, hence we
                # refresh it regularly
                con = AuthServiceProxy(
                    "http://%s:%s@127.0.0.1:%s" % (
                        State.RPC_USER, State.RPC_PASSWORD, PORT))
                try:
                    for u in range(0, n, 1):
                        # Generate users
                        user = User(
                            service=SERVICE,
                            network_size=randint(0, 255),
                            user_size=randint(0, 255),
                            capabilities=bytes([]),
                            nonce=get_random_bytes(NONCE_LENGTH)
                        )
                        user.request(s)
                    s.generate(1)

                    bh = con.getblockhash(con.getblockcount())
                    json = con.getblock(bh, 2)  # get JSON with simplified
                    # transactions

                    sizes = []
                    vsizes = []
                    if json['nTx'] != n + 1:
                        # Sanity check
                        # +1 is for the change address
                        raise RuntimeError(
                            'Unexpected transaction in block!')
                    for tx in json['tx']:
                        sizes.append(tx['size'])
                        vsizes.append(tx['vsize'])

                    size = float(json['size'])
                    weight = json['weight']
                    stripped_size = json['strippedsize']
                    avg_tx_size = (size - EMPTY_BLOCK_SIZE) / max(n, 1)
                    if n != 0:
                        avg_real = float(
                            statistics.mean([s for s in sizes if
                                             s not in coinbase_sizes]))  #
                        # Strip of the coinbase transaction
                        avg_vsize = float(
                            statistics.mean([s for s in vsizes if
                                             s not in coinbase_avg_sizes]))
                        # Strip of the coinbase transaction
                    else:
                        avg_real = 0.0
                        avg_vsize = 0.0
                    if avg_real != avg_tx_size:
                        # raise RuntimeError('The computed average
                        # transaction size not as expected! %d vs %d' %
                        #                    (avg_tx_size, avg_real))
                        print(
                            'The computed average transaction size not '
                            'as expected! {} vs {}'.format(
                                avg_tx_size, avg_real))
                    with open(file_path, 'a') as fd:
                        fd.write('{};{};{};{};{};{};{};{};{}\n'.format(
                            n, r, int(size), int(stripped_size), weight,
                            avg_real, avg_vsize, sizes, vsizes))
                    completed = True
                except BrokenPipeError:
                    # Just try again, those error are not avoidable
                    # unfortunately...
                    error_count += 1
                    if error_count > 100:
                        raise BrokenPipeError(
                            "More than 100 broken pipe errors...")
