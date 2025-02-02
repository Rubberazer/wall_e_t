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
    uint32_t count = 0;
    query_return_t query_insert = {0};
    
    err = create_wallet_db("wallet");
    if (err) {
	fprintf(stderr, "Problem creating database file, exiting\n");
    }
        
    strcpy(query_insert.value, "a2c20798f8631fcaca9b4c364111b2651fa7966ced524f474e9eeed9a82b6c74");
    query_insert.id = 0;
    
    err = insert_key(&query_insert, 1, "wallet", "account", "private_key");
    if (err < 0) {
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	exit(err);
    }
    
    err = query_count("wallet", "account", "private_key", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    count = err;
    printf("Number of rows returned: %u\n", count);
    
    query_return_t query_return[err];
    
    err = read_key(query_return, "wallet", "account", "private_key", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    for (uint32_t i =0; i < count; i++ ) {
	printf("Values returned, index:%d and value: %s\n", query_return[i].id, query_return[i].value);	
    }
    
    exit(EXIT_SUCCESS);	
}
