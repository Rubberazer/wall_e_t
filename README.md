# wall_e_t
Bitcoin wallet and the collection of functions to build your own, all written in C.

This software implements the following standards or BIPs (Bitcoin Improvement Proposals):
 - [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) Hierarchical Deterministic Wallets
 - [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) Mnemonic code for generating deterministic keys
 - [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) Multi-Account Hierarchy for Deterministic Wallets
 - [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) Derivation scheme for P2WPKH based accounts
 - [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) Base32 address format for native v0-16 witness outputs
 
## Acknowledgments
This software package is built upon the shoulders of the [libgcrypt](https://www.gnupg.org/software/libgcrypt/index.html), [SQLite](https://www.sqlite.org/copyright.html) and [libcurl](https://curl.se/docs/copyright.html) libraries, all honour and glory to those developers.
Also code snippets from the reference implementation of [BIP173](https://github.com/sipa/bech32/tree/master/ref) have been used to calculate bech32 type of address checksums.
Balances are coming through a web API, more specifically, this one: https://blockchain.info

## Dependencies
In order to compile, you will need to install libgcrypt, SQLite and libcurl first e.g. on a Debian based system this should be as simple as:

    sudo apt install libgcrypt20-dev && sudo apt install libsqlite3-dev	&& \
    sudo apt install libcurl4-openssl-dev

## Test vectors
Some, but not all of the test vectors included at the end of the concerned BIPs, plus numerous (lots) of tries here: https://iancoleman.io/bip39, all looking good at this point, extremely useful site by the way. Also, Greg's site is an absolute must, highly recommended: https://learnmeabitcoin.com/.

## Is it safe?
Very early development so at this point you shouldn't put any serious funds into the wallet itself, the way I look at this project is more educational e.g. example of how to develop a wallet in C and not using the ubiquitous OpenSSL. So far it is better to use the code to play yourself and maybe create your own wallets and see how it is done.

## Tests
You can just compile the tests:

    make tests

This above will produce 5 executable files, if you run this one: ./test_BIP84 what you will get is basically a full BIP84 wallet derived from mnemonics up to the change addresse(s), read the code to see what is going on. 

## The Wallet
You should compile with:
	
	make wallet
 
This will generate an executable: wall_e_t, options are:

[wall_e_t_demo](https://github.com/user-attachments/assets/11cc3800-bc18-461e-9366-f40d5ddbe2cf)


### Create wallet
This will create a wallet with a mnemonic phrase so you can recover it in the future

	./wall_e_t -create
	
### Recover wallet
This will recover your wallet starting from a mnemonic phrase and an optional passphrase 

	./wall_e_t -recover

### Receive
This will create a new bitcoin address so you can receive coins, and store this address in your wallet

    ./wall_e_t -receive
	
### Show key
This will show your Private Root key on screen 

	./wall_e_t -show key

### Show Addresses
This will show all your bitcoin addresses on screen

    ./wall_e_t -show addresses

### Show keys
This will show all your bitcoin addresses with their respective private keys on screen

    ./wall_e_t -show keys

### Balance
This will show on screen the amount of satoshis per bitcoin address and the totals in your wallet

    ./wall_e_t -balance
	
### Transaction (not ready yet)
It will generate a raw transaction based on a single input and 2 potential outputs

    ./wall_e_t -transaction

### Transfer (not ready yet)
To transfer your coins to some other address

    ./wall_e_t -transfer

