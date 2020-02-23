#!/usr/bin/python3
"""
This file contains an exemplary implementation of Bitcoin-like
PoW for AnonBoot peer advertisements. For real application it
is advised to replace this with a memory-hard PoW scheme to
decrease the performance advantages achievable by dedicated
mining hardware.
"""
import hashlib

# How many leading 0s required for PoW?
from typing import Union

POWORK_DIFFICULTY = 0
# Length of NONCE within Peer Advertisements
NONCE_LENGTH = 8


def calculate_powork(
        peer_pubkey: bytes,
        merkle: str,
        difficulty: int = POWORK_DIFFICULTY
    ) -> bytes:
    """
    Computes a valid proof of work for the given public key
    and merkleroothash.

    :peer_pubkey: bytes:
        Public key of the peer perfoming the PoW
    :merkle: str:
        Merkleroothash of the last pulse block
    :difficulty: int:
        Difficulty level of the PoW
    :return: bytes:
        A nonce fulfilling the PoW condition
    """
    # Currently the whole pow field is the nonce
    seed = _calc_powork_seed(peer_pubkey, merkle)

    return _calculate_hash_powork_nonce(difficulty, seed, NONCE_LENGTH)


def _calc_powork_seed(peer_pubkey: bytes, merkle: str) -> bytes:
    """
    Compute seed for PoW computation.
    The PoW seed consists of the peer's Pubkey and the merkleroothash of the
    last L_S block.

    peer_pubkey: bytes:
        Public key of the peer perfoming the PoW
    :merkle: str:
        Merkleroothash of the last pulse block
    :return: bytes:
        The seed for the PoW computations
    """
    seed_hash = hashlib.sha256()
    seed_hash.update(peer_pubkey)
    seed_hash.update(bytes(merkle, 'utf-8'))
    return seed_hash.digest()


def _calculate_hash_powork_nonce(
        difficulty: int,
        seed: bytes,
        nonce_length: int,
        eval_active: bool = False
    ) -> Union[bytes, int]:
    """Compute a valid proof of work for the given difficulty and seed.

    :difficulty: int:
        Difficulty level of the PoW
    :seed: bytes:
        The seed for the PoW computation
    nonce_length: int:
        Length of nonce in bytes
    eval_active: bool:
        Whether this function was called during the pow_eval
    :return: Union[bytes, int]
        Usually a suitable nonce is returned, but during eval the number of
        hash computations to create such a nonce is returned

    """
    c = 0
    nonce_bits = nonce_length * 8
    for n in range(2 ** nonce_bits):
        if eval_active:
            c += 2  # 2 SHA256 per validation
        nonce = n.to_bytes(nonce_length, byteorder='big')
        if _validate_hash_powork(difficulty, seed + nonce):
            if not eval_active:
                return nonce
            else:
                # Only for eval (Number of OPs instead of nonce)
                return c

    raise ValueError(
        "No valid powork possible")  # Should actually never happen


def _validate_hash_powork(difficulty: int, powork: bytes) -> bool:
    """Check whether the proof of work fulfills the difficulty demands.

    The difficulty is given as number of leading 0.
    E.g. a diffulty of 4 means that powork has to be smaller than 0001....

    :difficulty: int:
        Difficulty level of the PoW, see above explanation
    :powork: bytes:
        The seed + nonce to validate
     :return: bool:
        True if the given PoW is valid, False otherwise
    """
    powork_bits_amount = len(powork) * 8
    target = 2 ** (powork_bits_amount - difficulty)

    first = hashlib.sha256(powork).digest()
    second = hashlib.sha256(first).digest()

    if int.from_bytes(second, byteorder='big') < target:
        return True
    else:
        return False


def validate_powork(
        nonce: bytes,
        peer_pubkey: bytes,
        merkle: str
    ) -> bool:
    """
    Check whether the given nonce and context form a valid PoW.

    :nonce: bytes:
        The nonce to validate
    :peer_pubkey: bytes:
        The public key of the peer that procude(s/d) the PoW
    :merkle: str:
        Merkleroothash of the pulse block responsible
    :return: bool:
        True, if the nonce is valid for the given context
    """
    seed = _calc_powork_seed(peer_pubkey, merkle)
    powork = bytes(seed + nonce)
    return _validate_hash_powork(POWORK_DIFFICULTY, powork)
