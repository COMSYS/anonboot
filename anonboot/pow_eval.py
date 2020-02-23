#!/usr/bin/python3
"""
This script evaluates how many hash operations are necessary
to satisfy a certain target difficulty of the protocol.
"""
from _sha256 import sha256
import sys

from progressbar import progressbar
from Cryptodome.Random.random import choice, getrandbits

from eval import get_peers, get_pow_eval_path, get_timestamp
from pow import _calc_powork_seed, _calculate_hash_powork_nonce, NONCE_LENGTH
from parser.pow import pow_parser


def get_filename(reps: int, min_val: int, max_val: int, step: int, end: str =
                 '.csv') -> str:
    """Return the pow filename for the given parameters"""
    return "{}_pow_{}reps_{}to{}step{}{}".format(get_timestamp(), reps,
                                                 min_val,
                                                 max_val, step, end)


if __name__ == '__main__':

    args = pow_parser.parse_args()

    REPS = args.reps if args.reps is not None else 1000

    MIN = args.MIN
    MAX = args.MAX
    STEP = args.STEP

    # Load peers
    try:
        peers = get_peers(10000)
    except FileNotFoundError:
        print("File peers/peers_10000.pyc does not exist. Execute "
              "'anonboot/generate_peers.py 10000'.")
        sys.exit()

    filename = get_pow_eval_path() + '/' + get_filename(REPS, MIN, MAX, STEP)
    eval_dir = get_pow_eval_path()
    with open(filename, 'w') as fd:
        fd.write("------------------------HEADER------------------------\n")
        fd.write("PoW Eval")
        fd.write(
            "Difficulty (from, to, step): {}\n".format(str((MIN, MAX, STEP))))
        fd.write("Repetitions per config: {}\n".format(REPS))
        fd.write("Difficulty; # Hash Operations; Repetition\n")
        fd.write("----------------------END-HEADER----------------------\n")
    for r in progressbar(range(0, REPS)):
        for diff in range(MIN, MAX, STEP):
            hash_operations = 0

            # We use pre-generated but 'real' public keys, chosen randomly
            pubkey = choice(peers).public_key_hash()
            # We use a random merkleroothash
            merkle = sha256(getrandbits(256).to_bytes(32, 'big')).digest().hex()

            seed = _calc_powork_seed(pubkey, merkle)
            hash_operations += 1  # One hash operation for seed computation

            hash_operations += _calculate_hash_powork_nonce(diff, seed,
                                                            NONCE_LENGTH,
                                                            True)

            # Write Result
            with open(filename, 'a') as fd:
                fd.write('{};{:d};{}\n'.format(diff, hash_operations, r))
