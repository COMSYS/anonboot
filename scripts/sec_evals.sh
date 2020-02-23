#!/usr/bin/env bash

REPS=10000 # number of repetitions per config
USER_SIZE=100 # number of users in generated NWs
MIN_PEER=4 # Min, max and stepsize of the number of peers in created NWs
MAX_PEER=100
STEP_PEER=3

for PEERS in 500 1000 5000 10000 50000 10000 ; do
    for (( MAL = 0; MAL < 51; MAL += 5 )); do
        python3 anonboot/security_eval.py -m $MAL $MAL 1 -r $REPS -p $PEERS -u $USER_SIZE -s $MIN_PEER $MAX_PEER $STEP_PEER
    done
    # Special case with 1/3 mal peers
    python3 anonboot/security_eval.py -m 33 33 1 -r $REPS -p $PEERS -u $USER_SIZE -s $MIN_PEER $MAX_PEER $STEP_PEER
done


