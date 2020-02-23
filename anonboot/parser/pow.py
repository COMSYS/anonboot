#!/usr/bin/python3
"""
Parser for PoW eval
"""
from argparse import ArgumentParser

pow_parser = ArgumentParser(description='Parser for PoW Evaluation')
pow_parser.add_argument(
    '-r',
    '--reps',
    help="Number of Repetitions",
    dest='reps',
    type=int,
    action='store'
)
pow_parser.add_argument(
    'MIN',
    help="Minimal Value of Loop",
    action='store',
    type=int
)
pow_parser.add_argument(
    'MAX',
    help="Maximal Value of Loop",
    action='store',
    type=int
)
pow_parser.add_argument(
    'STEP',
    help="Step Value of Loop",
    action='store',
    type=int
)
