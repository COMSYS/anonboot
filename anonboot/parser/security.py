#!/usr/bin/python3
"""
Parser for security eval
"""
from argparse import ArgumentParser

security_parser = ArgumentParser(description='Parser for Security Evaluation')
security_parser.add_argument(
    '-m',
    '--malicious',
    help="Malicious Nodes Range",
    dest='malicious',
    type=int,
    nargs=3,
    action='store',
    required=True
)
security_parser.add_argument(
    '-s',
    '--peer_size',
    help="Peer Size Range",
    dest='peer_size',
    type=int,
    nargs=3,
    action='store',
    required=True
)
security_parser.add_argument(
    '-r',
    '--reps',
    help="Number of Reps",
    dest='reps',
    type=int,
    action='store'
)
security_parser.add_argument(
    '-p',
    '--peers',
    help="Number of Peers",
    dest='peers',
    type=int,
    action='store'
)
security_parser.add_argument(
    '-u',
    '--user_size',
    help="# Users in Network",
    dest='user_size',
    type=int,
    action='store'
)
