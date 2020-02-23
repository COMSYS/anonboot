#!/usr/bin/python3
"""
This file generates a certain number of valid
public/private key pairs and writes them into a file.
"""
import os
import pickle
from sys import argv

from progressbar import progressbar

from helpers import generate_key_pair


def generate_keys(num_keys: int) -> list:
    """Generate the given number of trees."""
    keys = []
    for _ in progressbar(range(0, num_keys)):
        keys.append(generate_key_pair())
    return keys


def store_keys(keys: list) -> None:
    """Store the list of keys to a pickle file."""
    num = len(keys)

    # create dir folder if it does not exist
    my_path = '/'.join(
        os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
    working_dir = my_path + "/../state"  # Path to peer files
    # Create folder if it does not exist:
    try:
        os.mkdir(working_dir)
    except FileExistsError:
        pass
    filename = "/keys_" + str(num) + ".pyc"
    with open(working_dir + filename, 'wb') as fd:
        pickle.dump(keys,
                    fd)  # We write a binary file to make usage simpler
    print("Wrote keys to '" + working_dir + filename + "'.")


def get_keys(num: int) -> list:
    """Return a list of peers loaded from the corresponding file."""
    my_path = '/'.join(
        os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
    working_dir = my_path + "/../bin"  # Path to peer files
    file = working_dir + "/keys_%d.pyc" % num
    with open(file, 'rb') as fd:
        return pickle.load(fd)


if __name__ == '__main__':
    if len(argv) != 2:
        print("Usage: generate_keys.py NUM_KEYS")
    else:
        store_keys(generate_keys(int(argv[1])))
