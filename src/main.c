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
#include <wall_e_t.h>

static struct option options[] = {
    {"create",  0, NULL, 'c'},
    {"recover", 0, NULL, 'r'},
    {"help",    0, NULL, 'h'},
    {"show",    2, NULL, 's'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv) {
    gcry_error_t err = 0;
    //int32_t error = 0;
    int32_t opts = 0;
    int32_t option_index = 0;

    while ( opts != -1) {
	opts = getopt_long_only(argc, argv, "crhs:", options, &option_index);
	switch (opts) {
	case '1':
	case 'c': fprintf(stdout, "Create wallet\n");
	    break;
	case 's': fprintf(stdout, "show with flag: %s\n", optarg);
	    break;
	case 'r': fprintf(stdout, "Recover wallet\n");
	    break;
	case 'h': print_usage();
	    break;
	case '?': print_usage();
	    break;
	default: print_usage();
	}
    }
    
    exit(err);	
}
