#!/usr/bin/python3

import hashlib
import inspect
import ipaddress
import random
import sys

import ecdsa

import opreturn
import protocol
import pow


def generate_peers(keys: list, num: int) -> list:
    """Return a list of valid peers"""
    peers = []
    for i in range(num):
        (pri, pub) = keys.pop()
        tx = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
        # Constant tx because it does not matter for eval
        p = protocol.Peer(
            ip_address=ipaddress.IPv4Address(get_random_bytes(4)),
            port=int(random.randint(3000, 4000)),
            public_key=pub.to_string(),
            private_key=pri.to_string(),
            cont_tx=opreturn.Transaction(tx, 0),
            service=bytes([0x01, 0x00])  # All peers use standard service
        )
        peers.append(p)
    return peers


def generate_users(num: int) -> list:
    """Return a list of valid user requests"""
    users = []
    for i in range(num):
        dummy_capabilities = protocol.int_to_bytes(i)
        u = protocol.User(
            service=bytes([0x01, 0x00]),
            network_size=0,
            user_size=1,
            capabilities=dummy_capabilities,
            nonce=get_random_bytes(pow.NONCE_LENGTH),
        )
        users.append(u)
    return users


def comp_state_size(state) -> int:
    """Computes size of a state object"""
    size = 0
    size += get_size(state.l_v)
    size += get_size(state.l_s)
    size += get_size(state.expiration_height)
    size += get_size(state.fuzzy)
    size += get_size(state.current_block)
    size += get_size(state.networks)
    size += get_size(state.peers)
    size += get_size(state.times_seen)
    size += get_size(state.consecutive_seen)
    return size


def comp_peer_info_size(state) -> (int, int, int, int):
    """
    :return: int, int, int:
        Tuple consisting of total size of peer information, size of contact information, size of capabilities, and misc
    """

    size_total = get_size(state.peers)
    size_contact_info = 0
    size_capabilities = 0
    size_misc = 0

    for peer in state.peers.values():
        size_contact_info += get_size(peer.direct_pubkey) \
            + get_size(peer.is_ipv6) \
            + get_size(peer.address) \
            + get_size(peer.port) \
            + get_size(peer.pubkey)
        size_capabilities += get_size(peer.service) + get_size(peer.capabilities)
        size_misc += get_size(peer.block) + get_size(peer.cont_tx)

    return (size_total, size_contact_info, size_capabilities, size_misc)


def comp_network_info_size(state) -> (int, int, int):
    """
    :return: int, int, int:
        Tuple consisting of total size of network information, size of peers' contact information, and size of network parameters
    """

    size_total = get_size(state.networks)
    size_peer_infos = 0
    size_parameters = 0

    for network in state.networks:
        size_peer_infos += get_size(network.peers)
        size_parameters += get_size(network.service) + get_size(network.capabilities)

    return (size_total, size_peer_infos, size_parameters)


def get_random_bytes(n: int) -> bytes:
    """Return n random bytes."""
    return bytes([random.getrandbits(8) for _ in range(n)])


def string_to_trans(trstr: str) -> opreturn.Transaction:
    """ Extracts a transaction from a string"""
    vout = int(trstr[-1:])
    txid = trstr[:-2]
    return opreturn.Transaction(txid, vout)


def trans_to_string(trans: opreturn.Transaction) -> str:
    """ Convert transaction into simple string"""
    return trans.txid + ":" + str(trans.vout)


def generate_key_pair() -> tuple:
    """return a valid ecdsa.SECP256k1 key pair"""
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


if __name__ == '__main__':
    (priv_key, pub_key) = generate_key_pair()
    print('Private key: 0x', priv_key.to_string().hex().strip(), ' Length: ',
          len(priv_key.to_string()))
    print('Public key: 0x', pub_key.to_string().hex().strip(), ' Length: ',
          len(pub_key.to_string()))
    hash_val = hashlib.sha256(pub_key.to_string())
    print('Public Key hash: ', hash_val.hexdigest(), ' Length: ',
          len(hash_val.digest()))
