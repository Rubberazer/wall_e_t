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
    gcry_error_t error = GPG_ERR_NO_ERROR;
    int32_t err = 0;
    uint32_t count = 0;
    query_return_t query_insert = {0};
    key_pair_t keys[2] = {0};
    
    err = create_wallet_db("wallet");
    if (err) {
	fprintf(stderr, "Problem creating database file, exiting\n");
    }

    error = char_to_uint8("a2c20798f8631fcaca9b4c364111b2651fa7966ced524f474e9eeed9a82b6c74", keys[0].key_priv, 64);
    if (error) {
	fprintf(stderr, "Problem converting char to uint8\n");
	err = -1;
	return err;
    }
    
    query_insert.id = 0;
    err = encrypt_AES256((uint8_t *)query_insert.value, keys[0].key_priv, 32, "abc&we45./");
    if (err) {
	printf("Problem encrypting message, error code:%d", err);
    }
    
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
    
    err = decrypt_AES256(keys[1].key_priv, (uint8_t *)query_return[0].value, strlen(query_return[0].value), "abc&we45./");
    if (err) {
	printf("Problem decrypting message, error code:%d", err);
    }

    for (uint32_t i =0; i < count; i++ ) {
	printf("Values returned, index:%d value: %s and string length: %lu\n", query_return[i].id, query_return[i].value, strlen(query_return[i].value));
    }

    printf("\nDecrypted key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", keys[1].key_priv[i]);
    }
    printf("\n");
	   
    exit(EXIT_SUCCESS);	
}
