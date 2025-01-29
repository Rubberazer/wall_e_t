# wall_e_t
Bitcoin wallet and the collection of functions to build your own, all written in C (ONGOING/NOT FINISHED).

This software implements the following standards or BIPs (Bitcoin Improvement Proposals):
 - [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) Hierarchical Deterministic Wallets
 - [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) Mnemonic code for generating deterministic keys
 - [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) Multi-Account Hierarchy for Deterministic Wallets
 - [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) Derivation scheme for P2WPKH based accounts
 - [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) Base32 address format for native v0-16 witness outputs
 
## Acknowledgments
This software package is built upon the shoulders of the [libgcrypt](https://www.gnupg.org/software/libgcrypt/index.html) and [SQLite](https://www.sqlite.org/copyright.html) libraries, all honour and glory to those developers.
Also code snippets from the reference implementation of [BIP173](https://github.com/sipa/bech32/tree/master/ref) have been used to calculate bech32 type of address checksums.

## Dependencies
In order to compile, you will need to install libgcrypt and SQLite first e.g. on a Debian based system this should be as simple as:

    sudo apt install libgcrypt20-dev
    sudo apt install libsqlite3-dev	

## Test vectors
Some, but not all of the test vectors included at the end of the concerned BIPs, plus numerous (lots) of tries here: https://iancoleman.io/bip39, all looking good at this point, extremely useful site by the way. Also, Greg's site is an absolute must, highly recommended: https://learnmeabitcoin.com/.

## Done so far
Probably the most useful thing you can do at this point is just to compile the tests:

    make tests

This above will produce 4 executable files, if you run this one: ./test_BIP84 what you will get is basically a full BIP84 wallet derived from mnemonics up to the change addresse(s), read the code to see what is going on. 
