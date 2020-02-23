#!/usr/bin/python3
"""
This file contains functionality shared by all eval scripts.
"""
import os
import pickle
from datetime import datetime
from bitcoinrpc.authproxy import AuthServiceProxy

import opreturn
import protocol


def get_eval_dir() -> str:
    """Return eval dir and create eval dir if it does not exist"""
    # Path to this script
    my_path = '/'.join(os.path.realpath(__file__).split('/')[0:-1])
    # Path for Eval Results
    eval_dir = my_path + "/../eval"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_txnum_eval_path() -> str:
    """Return path for results of maximum block size eval"""
    # Path for Eval Results
    eval_dir = get_eval_dir() + "/txnum"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_size_eval_path() -> str:
    """Return path for results of size eval"""
    # Path for Eval Results
    eval_dir = get_eval_dir() + "/adsize"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_timestamp() -> str:
    """Return a string timestamp to include into the filename"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d-%H-%M-%S")


def get_user_size_eval_path() -> str:
    """Return path for results of size eval"""
    # Path for Eval Results
    eval_dir = get_eval_dir() + "/user_size"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_security_eval_path() -> str:
    """Return path for results of security eval"""
    # Path for Eval Results
    eval_dir = get_eval_dir() + "/security"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_pow_eval_path() -> str:
    """Return path for results of PoW eval"""
    # Path for Eval Results
    eval_dir = get_eval_dir() + "/pow"
    try:
        os.mkdir(eval_dir)
    except FileExistsError:
        pass
    return eval_dir


def get_peers(num_peers: int) -> list:
    """Return a list of peers loaded from the corresponding file."""
    my_path = '/'.join(
        os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
    peer_dir = my_path + "/../peers"  # Path to peer files
    peer_file = peer_dir + "/peers_%d.pyc" % num_peers
    with open(peer_file, 'rb') as fd:
        return pickle.load(fd)


def generate_valid_source_tx(
        s: protocol.State,
        con: AuthServiceProxy,
        max_tx: int
    ) -> None:
    # Transmit enough funds to addresses so that we won't need
    # to use coinbase transactions.
    # There are at most MAX many transactions in one step. Hence,
    # we need at most that many different addresses. (We can always
    # use the change addresses because our transactions have nearly
    # no costs)

    num_addr = max_tx // 10  # We want at most 50 advertisements to use the
    # same address
    s.source_tx = []

    start = con.getblockcount() + 1
    con.generate(num_addr + 101)
    top = con.getblockcount()

    interval = range(start, top - 100)
    block_hashes = con.batch_([["getblockhash", h] for h in interval])
    blocks = con.batch_([["getblock", ha, 2] for ha in block_hashes])
    del block_hashes
    txs = [block['tx'][0] for block in blocks]
    del blocks

    sent_txs = []
    i = 0
    value = -1
    txid = -1
    n = -1
    for tx in txs:
        for out in tx['vout']:
            if out['scriptPubKey']['type'] == 'pubkey':
                # The pubkey transactions are coinbase transactions because
                value = out['value']
                txid = tx['txid']
                n = out['n']
        if value == -1 or txid == -1 or n == -1:
            raise RuntimeError("No coinbase transaction found.")
        addr = con.getnewaddress()
        sent_value = float(value) / 2  # create two addresses per transaction
        raw_tx = con.createrawtransaction([{'txid': txid, 'vout': n}], {
            addr: sent_value})  # The - is for the fees
        funded_tx = con.fundrawtransaction(raw_tx)
        signed_tx = con.signrawtransactionwithwallet(funded_tx["hex"])
        if signed_tx["complete"] is False:
            raise RuntimeError(
                "bitcoind could not sign the transaction. (During "
                "Initialization)")
        txid = con.sendrawtransaction(signed_tx["hex"])
        sent_txs.append(txid)

        i += 1

        # Create a block each 100 transactions
        if i == 100:
            con.generate(1)
            i = 0

    con.generate(1)

    txs = con.batch_([['getrawtransaction', txid, 1] for txid in sent_txs])
    for tx in txs:
        for out in tx['vout']:
            vout = out['n']
            s.source_tx.append(opreturn.Transaction(tx['txid'], vout))
    c = 0
    for utxo in s.source_tx:
        if not protocol.is_valid_utxo(utxo):
            c += 1
    print("Found %d invalid utxos." % c)
