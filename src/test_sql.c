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
#include <errno.h>
#include <wall_e_t.h>

int main(int arg, char *arv[]) {
    int32_t err = 0;   
    
    err = create_wallet_db("wallet");
    if (err) {
	fprintf(stderr, "Problem creating database file, exiting\n");
    }
    
    err = query_count("wallet", "account", "public_key", NULL);
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    printf("Number of rows returned: %d\n", err);

    /*
    return_query = read_key("wallet", "account", "public_key_address", all, decrypted);
	if (return_query.index < 0) {
	fprintf(stderr, "Problem with query.\n");
	exit(return_query.count);
	}*/
       
    exit(EXIT_SUCCESS);	
}
