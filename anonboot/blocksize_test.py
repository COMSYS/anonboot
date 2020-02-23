#!/usr/bin/python3
"""
This module test the maximal number of TXs in one block.
"""
import math
import logging
import sys
from collections import deque
from bitcoinrpc.authproxy import AuthServiceProxy
import socket

from eval import get_txnum_eval_path
from protocol import State
from generate_keys import get_keys
from helpers import generate_peers

PORT = 18445
filepath = get_txnum_eval_path() + '/' + 'max_tx_num.txt'


def write(text: str) -> None:
    """Both log to console and write into output file"""
    logger.info(text)
    with open(filepath, 'a') as fd:
        fd.write(text)
        fd.write('\n')


def connect() -> AuthServiceProxy:
    """Establish a fresh connection to the deamon"""
    return AuthServiceProxy(
        "http://%s:%s@127.0.0.1:%s" % (
            State.RPC_USER, State.RPC_PASSWORD, PORT))


if __name__ == '__main__':
    # Logging
    LOG_LEVEL = logging.DEBUG
    logger = logging.getLogger("Blocksize Test")
    logger.setLevel(LOG_LEVEL)
    handler = logging.StreamHandler()
    handler.setLevel(LOG_LEVEL)
    logger.addHandler(handler)

    try:
        keys = get_keys(5000)
    except FileNotFoundError:
        logger.error(
            "There is no key-file bin/keys_10000.pyc. Call "
            "'anonboot/generate_keys.py "
            "10000' to create the necessary file.")
        sys.exit()

    # Generate Peers
    peers = generate_peers(keys, 5000)

    # Generate addresses
    NUM_ADDRESSES = int(len(peers) / 20)
    logger.info(
        "Generate {} addresses!".format(math.ceil(NUM_ADDRESSES / 50) * 50))
    # Bitcoin allows each address to be used at most 25 times per block.

    # We have to do this in several rounds because preserver has problems with
    # socket timeouts.
    a_counter = {}
    inputs = deque()
    for _ in range(0, NUM_ADDRESSES, 50):
        complete = False
        while not complete:
            try:
                addresses = connect().batch_(
                    ['getnewaddress'] for i in range(50))
                blocks = [b[0] for b in connect().batch_(
                    [['generatetoaddress', 1, addr] for addr in addresses])]
                blocks = [block['tx'][0] for block in
                          connect().batch_(['getblock', b] for b in blocks)]
                raws = connect().batch_(
                    ['getrawtransaction', txid, 1] for txid in blocks)
                for r in raws:
                    for v in r['vout']:
                        if 'addresses' in v['scriptPubKey']:
                            vout = v['n']
                            addr = v['scriptPubKey']['addresses'][0]
                            val = v['value']
                            inputs.append(
                                {'in': {'txid': r['txid'], 'vout': vout},
                                 'addr': addr, 'amount': val})
                            a_counter[addr] = 0
                            break
                complete = True
            except socket.timeout as e:
                logger.warning("Socket timeout occured.")
    # Generate 101 blocks to make addresses usable
    connect().generate(101)
    logger.info("Address Generation Done!")

    errors = 0
    last_success = 0
    for i in range(5100, 5300, 1):
        if errors >= 2:
            # 2 consecutive fails occurred
            write("**********************************")
            write(
                "The largest block that could be mined contained {} "
                "TXs.".format(
                    i - 2))
            write("**********************************")
            break
        try:
            ads = []
            tmp_state = State(1, 1, 0)
            for p in peers[:i]:
                ads.append(p.advertise(tmp_state))
            print("Attempt to write {} advertisements".format(len(ads)))
            con = connect()
            for ad in ads:
                input = inputs.popleft()
                raw = con.createrawtransaction([input['in']], [{'data': ad}])
                funded = con.fundrawtransaction(raw, {
                    "changeAddress": input['addr']})
                signed = con.signrawtransactionwithwallet(funded['hex'])
                sent = con.sendrawtransaction(signed['hex'])
                raw = con.getrawtransaction(sent, 1)
                vout = -1
                new_value = input['amount'] - 1
                for v in raw['vout']:
                    if v['value'] >= new_value:
                        vout = v['n']
                        new_value = v['value']
                        break
                if vout == -1:
                    logging.warning(
                        "WARNING: No suitable output found, will lead to "
                        "problems!")
                else:
                    inputs.append(
                        {'in': {'txid': raw['txid'], 'vout': vout},
                         'addr': input['addr'], 'amount': new_value})
            # For this eval we do not fill the remainder of the block
            # because it does not have an influence.
            connect().generate(1)
            # No error
            write("Successfully mined a block with {} TXs.".format(i))
            errors = 0
        except Exception as e:
            write("The following error occured: {}".format(str(e)))
            write("Did not manage to write block with {} TXs.".format(i))
            errors += 1
