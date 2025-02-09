/* Bitcoin wallet on the command line based on the libgcrypt & SQLite libraries
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
    {"help",    0, NULL, 'h'},
    {NULL, 0, NULL, 0}
    };

    while ( opts != -1) {
	if ((argc < 2) || (argc > 4)) {
	    print_usage();
	    exit(err);
	}
	opts = getopt_long_only(argc, argv, "crhs:", options, NULL);
	switch (opts) {
	case 'c':
	    opt_mask = 0x01;
	    break;
	case 'r':
	    opt_mask = 0x02;
	    fprintf(stdout, "Recover wallet\n");
	    break;
	case 'R':
	    opt_mask = 0x04;
	    fprintf(stdout, "Receive bitcoin\n");
	    break;
	case 's':
	    fprintf(stdout, "show\n");
	    for (uint32_t i = optind-1; i < argc; i++)
		printf ("Arguments %s\n", argv[i]);
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

    
    
    exit(err);	
}
