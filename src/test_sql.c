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
    query_return_t insert_address = {0};
    query_return_t recover_address = {0};
    key_pair_t keys[2] = {0};
    char *password = "abc&we45dsad./";
    
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
    err = encrypt_AES256(query_insert.value, (uint8_t *)(&keys[0]), sizeof(key_pair_t), password);
    if (err) {
	printf("Problem encrypting message, error code:%d", err);
    }
    
    err = insert_key(&query_insert, 1, "wallet", "account", "keys");
    if (err < 0) {
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	exit(err);
    }
    
    err = query_count("wallet", "account", "keys", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    count = err;
    printf("Number of rows returned: %u\n", count);
    
    query_return_t query_return[err];
    
    err = read_key(query_return, "wallet", "account", "keys", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }

    memset(keys[1].key_priv, 0, 32);
    // PKCS#7+IV length (16 bytes) for key_pair_t: 256 bytes
    uint32_t s_in_length = 0;
    if (!((sizeof(key_pair_t))%16)) {
	s_in_length = sizeof(key_pair_t)+16;
    }
    else {
	s_in_length = sizeof(key_pair_t)+(16-((sizeof(key_pair_t))%16));
    }
    s_in_length += 16;

    err = decrypt_AES256((uint8_t *)(&keys[1]), query_return[0].value, s_in_length, password);
    if (err) {
	printf("Problem decrypting message, error code:%d", err);
    }
    printf("\nDecrypted key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", keys[1].key_priv[i]);
    }
    printf("\n");

    char *bitcoin_address = "bc1q0cgzunwtnydaklsrrv8gc6frdm9tq2fdprydl6";
    insert_address.id = 0;
    memcpy(insert_address.value, bitcoin_address, strlen(bitcoin_address));
    
    err = insert_key(&insert_address, 1, "wallet", "receive", "address");
    if (err < 0) {
	fprintf(stderr, "Problem inserting address into database, exiting\n");
	exit(err);
    }
    
    err = read_key(&recover_address, "wallet", "receive", "address", "WHERE id=0");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    
    char bitcoin_adress_rec[100] = {0};
    memcpy(bitcoin_adress_rec, recover_address.value, strlen(bitcoin_address));
    
    printf("Bitcoin address: %s\n", bitcoin_adress_rec);
    
    exit(EXIT_SUCCESS);	
}
