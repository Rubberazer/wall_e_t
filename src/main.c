/* Bitcoin wallet on the command line based on the libgcrypt, SQLite
 * and libcurl libraries, made in its entirety by human hands   
 *
 * Copyright 2025 Rubberazer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <wall_e_t.h>

int main(int argc, char **argv) {
    int32_t err = 0;
    int32_t opts = 0;
    uint32_t opt_mask = 0;
    struct option options[] = {
    {"create",  0, NULL, 'c'},
    {"recover", 0, NULL, 'r'},
    {"receive", 0, NULL, 'R'},
    {"show",    1, NULL, 's'},
    {"balance", 0, NULL, 'b'},
    {"help",    0, NULL, 'h'},
    {NULL, 0, NULL, 0}
    };

    while ( opts != -1) {
	if ((argc < 2) || (argc > 4)) {
	    print_usage();
	    exit(err);
	}
	opts = getopt_long_only(argc, argv, "crRs:bh", options, NULL);
	switch (opts) {
	case 'c':
	    opt_mask = 0x01;
	    break;
	case 'r':
	    opt_mask = 0x02;
	    break;
	case 'R':
	    opt_mask = 0x04;
	    break;
	case 's':
	    if (!strcmp(argv[optind-1], "key")) {
		opt_mask = 0x08;
		break;
	    }
	    else if (!strcmp(argv[optind-1], "addresses")) {
		opt_mask = 0x10;
		break;
	    }
	    else if (!strcmp(argv[optind-1], "keys")) {
		opt_mask = 0x11;
		break;
	    }
	    else {
		fprintf(stdout, "Wrong argument for -show\n");
	    }
	    break;
	case 'b':
	    opt_mask = 0x12;
	    break;
	case 'h': print_usage();
	    break;
	}
	break;
    }

    if (opt_mask == 0x01) {
	err = create_wallet();
	if (err) {
	    fprintf(stderr, "Problem creating wallet, exiting\n");
	    exit(err);
	}
	else {fprintf(stdout, "Wallet created successfully\n");}
    }
    if (opt_mask == 0x02) {
	err = recover_wallet();
	if (err) {
	    fprintf(stderr, "Problem recovering wallet, exiting\n");
	    exit(err);
	}
	else {fprintf(stdout, "Wallet recovered successfully\n");}
    }    
    if (opt_mask == 0x04) {
	err = receive_coin();
	if (err) {
	    fprintf(stderr, "Problem generating new bitcoin address, exiting\n");
	}
    }    
    if (opt_mask == 0x08) {
	err = show_key();
	if (err) {
	    fprintf(stderr, "Problem showing Account key, exiting\n");
	}
    }    
    if (opt_mask == 0x10) {
	err = show_addresses();
	if (err) {
	    fprintf(stderr, "Problem showing addresses, exiting\n");
	}
    }    
    if (opt_mask == 0x11) {
	err = show_keys();
	if (err) {
	    fprintf(stderr, "Problem showing keys&addresses, exiting\n");
	}
    }    
    
    if (opt_mask == 0x12) {
	err = wallet_balances();
	if (err) {
	    fprintf(stderr, "Problem showing keys&addresses, exiting\n");
	}
    }    
    
    exit(err);	
}
