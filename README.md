# wall_e_t
Tools to develop Bitcoin wallets in C (ONGOING/NOT FINISHED)

## Acknowledgments
This software package is built upon the shoulders of the [libgcrypt](https://www.gnupg.org/software/libgcrypt/index.html) and [SQLite](https://www.sqlite.org/copyright.html) libraries, all honour and glory to those developers.
Also code snippets from the reference implementation of [BIP173](https://github.com/sipa/bech32/tree/master/ref) has been used to calculate bech32 type of address checksums.

## Dependencies
In order to compile, you will need to install libgcrypt and SQLite first e.g. on a Debian based system this should be as simple as:

    sudo apt install libgcrypt20-dev
    sudo apt install libsqlite3-dev	
