# AnonBoot

This repository contains our proof-of-concept implementation of AnonBoot, an architecture for securely bootstrapping anonymity services seizing a public blockchain as a trust anchor.
Through periodic peer advertisements, we create a Sybil-resistant repository of privacy peers that can be directly utilized to establish circuits for onion routing networks, or that can be elected to establish small distributed anonymity services such as mixnets or cryptotumblers.
This implementation shows how AnonBoot can operate even on simple public blockchains such as Bitcoin.

## Publications

*  Roman Matzutt, Jan Pennekamp, Erik Buchholz, Klaus Wehrle: Utilizing Public Blockchains for the Sybil-Resistant Bootstrapping of Distributed Anonymity Services. In 15th ACM ASIA Conference on Computer and Communications Security (ACM ASIACCS’20), ACM, accepted, 2020.

## Dependencies

* [`python-bitcoinrpc`](http://www.github.com/jgarzik/python-bitcoinrpc) (GNU Lesser General Public License v2.1)
* [`progressbar2`](https://github.com/WoLpH/python-progressbar) (BSD 3-Clause)
* [`ecdsa`](http://github.com/warner/python-ecdsa) (MIT)
* [`pycrypto`](https://github.com/dlitz/pycrypto) (Custom)
* [`pycryptodomex`](https://github.com/Legrandin/pycryptodome) (BSD 2-Clause)

Optionally, if you want to run the (GUI) demo, you need `tkinter`, which is not necessarily pre-installed for Python 3 on Ubuntu machines.
In that case, run:

```
$ sudo apt-get install python3-tk
```

## Setup Notes (Linux/MacOS)

You need to have Bitcoin Core version 0.17.1 in your root directory:

```
wget https://bitcoincore.org/bin/bitcoin-core-0.17.1/bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
tar -zxf bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
```

(On MacOS, use `wget https://bitcoincore.org/bin/bitcoin-core-0.17.1/bitcoin-0.17.1-osx64.tar.gz` instead)

## Interactive Demo

To run the interactive demo, you must first prepare a local Bitcoin blockchain (in regression test mode) with a set of randomly created available privacy peers before you can use the interactive GUI (and inspect created transactions further, e.g. via `bitcoin-cli.sh` or [`bitcoin-abe`](https://github.com/marioschlipf/bitcoin-abe)).

## Bitcoin Regression Testing

To start off with a clean local blockchain with funds pre-mined and distributed to the created peers, use:

```
$ ./reset_regtest.sh
```

This script is also used to reset the local blockchain whenever desired.

If you followed the setup above, you can start the downloaded Bitcoin client in regression test mode using

```
$ ./bitcoind.sh
```

This command starts the Bitcoin client in the foreground, hence you should execute this command in a dedicated terminal.

### Interactive Demo

We provide a rudimentary demo frontend written using `tkinter` meant to facilitate the simulation of peer advertisements and service requests.

To start the GUI, use:

```
$ python3 anonboot/demo.py
```

The GUI lets you create random peer advertisements and user requests via the respective buttons.
You can manually edit the messages before submitting them, but failure to match the predefined layout (`protocol.PeerAdvertisement.LAYOUT` and `protocol.UserRequest`) will result in errors.
This means, e.g., you must provide service IDs and capabilities in hex format, where service IDs must be exactly two bytes long and capabilities may not exceed a length of 12 bytes (since number of peers and user size take up one byte each in the field string by default).

Afterward, you can generate blocks to reach the next pulse block (default pulse duration is ten blocks) and update the GUI's view.

## Running the Evaluation

Before evaluation scripts, you must prepare fictive privacy peers (execute all commands from the root directory of your checkout of this repository), e.g. of size 10000:

```
$ ./scripts/gen_peers.sh
```

This script will create a subfolder `peers` containing pre-populated peer repositories of the sizes used in our evaluation.
These peer repositories contain privacy peers, their credentials, and their advertised services, respectively.

Furthermore, if the evaluation script requires a connection to `bitcoind`, run
```
$ ./reset_regtest.sh
```
and (in a separate terminal)
```
$ ./bitcoind.sh
```
before running the respective evaluation script.

### Running Evaluation Scripts

The evaluation scripts reside in the `anonboot/` folder, but have convenient wrapper scripts located in `scripts/`.
Evaluation results consist of CSV files with descriptive headers that are written into respective sub-folders `eval/${evalname}/`.

Particularly, we provide evaluation scripts for the following measurements:

* `scripts/pow_evals.sh`: Empirically measure the number of hash operations required to solve a peer advertisement's PoW puzzle for increasing difficulties.
* `scripts/sec_evals.sh`: Simulate peer election with increasing shares of privacy peers being controlled by an adversary and empirically assess his success chances to infiltrate bootstrapped anonymity services.
* `scripts/adsize_evals.sh`: For increasing capacity values, evaluate how many Bitcoin blocks it takes to hold up to 10k peer advertisements. (requires running `bitcoind`)
* `scripts/user_req_evals.sh`: [unused] Like `adsize_evals.sh`, but for users' service requests. (requires running `bitcoind`)

## Acknowledgements

This work has been funded by the German Federal Ministry of Education and Research (BMBF) under funding reference number 16DHLQ013.
The responsibility for the content of this publication lies with the authors.
Furthermore, the authors thank Jöran Wiechert for his technical help.
