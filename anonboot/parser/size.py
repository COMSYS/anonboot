#!/usr/bin/python3
"""
Parser for size eval
"""
from argparse import ArgumentParser

size_parser = ArgumentParser(description='Parser for Size Evaluation')
size_parser.add_argument(
    'MIN',
    help="Minimal Value of Loop",
    action='store',
    type=int
)
size_parser.add_argument(
    'MAX',
    help="Maximal Value of Loop",
    action='store',
    type=int
)
size_parser.add_argument(
    'STEP',
    help="Step Value of Loop",
    action='store',
    type=int
)
size_parser.add_argument(
    '-r',
    '--reps',
    help="Number of Reps",
    dest='reps',
    type=int,
    action='store'
)
size_parser.add_argument(
    '-p',
    '--peers',
    help="Number of Peers",
    dest='peers',
    type=int,
    action='store'
)
size_parser.add_argument(
    '--port',
    help="RPC Port of Bitcoin Deamon",
    dest='port',
    type=int,
    action='store'
)
