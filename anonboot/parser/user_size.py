#!/usr/bin/python3
"""
Parser for size eval
"""
from argparse import ArgumentParser

user_size_parser = ArgumentParser(
    description='Parser for User Size Evaluation'
)
user_size_parser.add_argument(
    'MIN',
    help="Minimal Value of Loop",
    action='store',
    type=int
)
user_size_parser.add_argument(
    'MAX',
    help="Maximal Value of Loop",
    action='store',
    type=int
)
user_size_parser.add_argument(
    'STEP',
    help="Step Value of Loop",
    action='store',
    type=int
)
user_size_parser.add_argument(
    '-r',
    '--reps',
    help="Number of Reps",
    dest='reps',
    type=int,
    action='store'
)
user_size_parser.add_argument(
    '--port',
    help="RPC Port of Bitcoin Deamon",
    dest='port',
    type=int,
    action='store'
)
