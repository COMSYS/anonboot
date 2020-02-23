#!/usr/bin/python3
import bitcoinrpc.authproxy as authproxy
from collections import namedtuple

# Maximum amount of data bytes that can be inserted into an OP_RETURN
# transaction
MAX_DATA_LENGTH = 80

OpData = namedtuple('OpData',
                    'hex block tx_in tx_out merkle')  # Creates tuple

Transaction = namedtuple('Transaction', 'txid vout')  # Creates tuple subclass


def send_data(
        rpc_connection: authproxy.AuthServiceProxy,
        hexdata: str,
        tx_ins: list = ()
    ) -> Transaction:
    """Creates, funds, signs and sends an OP_RETURN transaction including
    hexdata

    Parameters
    ----------
    rpc_connection : bitcoinrpc.authproxy.AuthServiceProxy
        The RPC connection to the bitcoind client

    hexdata : str
        The hex encoded data to be included in the transaction

    tx_ins : list, optional
        List of namedtuples 'Transaction', representing UTXOs to fund the
        transaction

    Returns
    -------
    Transaction
        Change UTXO

    Raises
    ------
    ValueError
        If hexdata is more than MAX_DATA_LENGTH bytes

    RuntimeError
        If the transaction could not be signed
    """

    if len(hexdata) / 2 > MAX_DATA_LENGTH:
        raise ValueError("hexdata too big")

    inputs = [{"txid": tx.txid, "vout": tx.vout} for tx in tx_ins]
    unfinished_tx = rpc_connection.createrawtransaction(
        inputs, {"data": hexdata})
    funded_tx = rpc_connection.fundrawtransaction(unfinished_tx)

    signed_tx = rpc_connection.signrawtransactionwithwallet(funded_tx["hex"])
    if signed_tx["complete"] is False:
        raise RuntimeError("bitcoind could not sign the transaction.")

    txid = rpc_connection.sendrawtransaction(signed_tx["hex"])

    change_utxo = Transaction(txid, funded_tx["changepos"])
    return change_utxo


def get_data_from_script_hex(script: str) -> str:
    """Parses an OP_RETURN script (as hex string) and returns the data
    contained in it

    Parameters
    ----------
    script : str
        The OP_RETURN script as hex string

    Returns
    -------
    str
        Data included in the transaction as hex string

    Raises
    ------
    ValueError
        If script is not a valid OP_RETURN script
    """

    # NOTE: We parse from hex-field, not asm-field, because for small values
    # the asm is decoded as integer
    # Sanity check that hex is a OP_RETURN transaction:
    if len(script) < 6 or script[0:2] != "6a":
        raise ValueError("Argument is not valid OP_RETURN script")
    sec = int(script[2:4], 16)
    if sec > 76:
        # NOTE: This is only invalid if OP_RETURN values cannot exceed 256
        # bytes, else 77/78 could be valid
        raise ValueError("Argument is not valid OP_RETURN script")

    if sec == 76:
        # Size is encoded in next byte
        size = int(script[4:6], 16)
        data = script[6:]
    else:
        size = sec
        data = script[4:]

    if len(data) / 2 != size:
        raise ValueError(
            "Argument is not valid OP_RETURN script: Size mismatch")

    return data


def get_data_from_block_range(
        rpc_connection: authproxy.AuthServiceProxy,
        block_min: int,
        block_max: int,
        modulo: int,
        fuzzyness: int
    ) -> list:
    """ Returns all data found in OP_RETURN transactions in the block range
        [block_min, block_max] as list of hex strings.

    Parameters
    ----------
    rpc_connection : bitcoinrpc.authproxy.AuthServiceProxy
        The RPC connection to the bitcoind client

    block_min : int
        Lower block range bound (included)
    block_max : int
        Upper block range bound (included)
    modulo : int
        Consider only blocks that have b mod modulo = 0
    fuzzyness : int
        Also consider a small intervall around above condition

    Returns
    -------
    list
        A list of OpData tuples containing a hex string representing the data
        found and the block height it was found as well as the potential
        catena-like input and output
    """
    interval = [i for i in range(block_min, block_max + 1) if
                (i % modulo) <= fuzzyness]
    block_hashes = rpc_connection.batch_(
        [["getblockhash", h] for h in interval])
    blocks = rpc_connection.batch_([["getblock", ha] for ha in block_hashes])
    del block_hashes

    res = []
    for b in blocks:
        merkle = b['merkleroot']
        raw_txs = rpc_connection.batch_([["getrawtransaction", t]
                                         for t in b["tx"]])
        txs = rpc_connection.batch_([["decoderawtransaction", r]
                                     for r in raw_txs])
        for t in txs:
            for out in t["vout"]:
                if out["scriptPubKey"]["type"] == "nulldata":
                    m_data = get_data_from_script_hex(
                        out["scriptPubKey"]["hex"])
                    m_height = b["height"]

                    # Catena continuation transaction is always FIRST input
                    first_tx = t['vin'][0]
                    m_input = _transaction_from_inputtx(first_tx)

                    # This is the OP_RETURN output, but we want the
                    # continuation output. Our transactions should always
                    # have exactly two outputs, so we can simply "switch"
                    vout = 1 if out["n"] == 0 else 0
                    m_output = Transaction(t['txid'], vout)
                    op_data = OpData(m_data, m_height, m_input, m_output, merkle)
                    res.append(op_data)

    return res


def _transaction_from_inputtx(txjson: dict) -> Transaction:
    """Creates a transaction object from a json belonging to transaction"""
    if 'coinbase' in txjson:
        res = Transaction(txjson['coinbase'], txjson['sequence'])
    else:
        res = Transaction(txjson['txid'], txjson['vout'])

    return res


def get_recent_data(
        rpc_connection: authproxy.AuthServiceProxy,
        amount: int,
        l_s: int,
        fuzzy: int
    ) -> list:
    """Returns all data included in OP_RETURN transactions from last `amount`
    blocks

    Parameters
    ----------
    rpc_connection : bitcoinrpc.authproxy.AuthServiceProxy
        The RPC connection to the bitcoind client
    amount : int
        Amount of recent blocks to search
    l_s : int
        Consider only blocks that have b mod modulo = 0
    fuzzy : int
        Also consider a small intervall around above condition

    Returns
    -------
    list
        A list of hex strings representing the data found in last amount blocks

    Raises
    ------
    ValueError
        If `amount` is bigger than number of blockchain blocks
    """

    block_max = rpc_connection.getblockcount()
    block_min = block_max - amount + 1
    if block_min < 1:
        raise ValueError("Argument too big: There are not that many blocks.")

    return get_data_from_block_range(rpc_connection, block_min, block_max,
                                     l_s, fuzzy)


def to_hex_string(string: str) -> str:
    """Converts UTF-8 string into its hex representation
    :param string: str
        The string to convert to hex
    :return:
        Hex representation of the given string
    """
    return string.encode('utf-8').hex()


def from_hex_string(hex_input: str) -> str:
    """Converts hex string into its UTF-8 representation
    :param hex_input: str
        The hex value that shall be converted to a string
    :return: str
        The resulting string
    """
    return bytes.fromhex(hex_input).decode('utf-8')
