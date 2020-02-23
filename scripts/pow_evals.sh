#!/usr/bin/env bash

for (( I = 310; I < 331; ++I )); do
    python3 anonboot/pow_eval.py -r 1000 $I $(( $I + 1 )) 1
done
