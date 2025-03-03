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
    memset(keys[0].key_priv_chain, 0x11, 64);
    
    query_insert.id = 0;
    query_insert.value_size = 1000;
    err = encrypt_AES256(query_insert.value, (uint8_t *)(&keys[0]), sizeof(key_pair_t), password);
    if (err) {
	printf("Problem encrypting message, error code:%d", err);
    }
    
    err = insert_key(&query_insert, 1, "wallet", "root", "keys");
    if (err < 0) {
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	exit(err);
    }
    
    err = query_count("wallet", "root", "keys", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }
    count = err;
    printf("Number of rows returned: %u\n", count);
    
    query_return_t query_return[err];
    
    err = read_key(query_return, "wallet", "root", "keys", "");
    if (err < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	exit(err);
    }

    memset(keys[1].key_priv, 0, 32);
   
    // Message: key_pair_t + Authentication tag + IV length (12 bytes)
    uint32_t s_in_length = 0;
    s_in_length = sizeof(key_pair_t)+16+12;
    
    err = decrypt_AES256((uint8_t *)(&keys[1]), query_return[0].value, s_in_length, "abc&we45dsad./");
    if (err) {
	printf("Problem decrypting message, error code:%d", err);
    }

    uint8_t verifier[64] = {0};
    memset(verifier, 0x11, 64);
    
    if (memcmp(keys[1].key_priv_chain, verifier, 64)) {
	fprintf(stdout, "Incorrect password\n");
	err = -1;
	return err;
    }

    printf("\nDecrypted key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", keys[1].key_priv[i]);
    }
    printf("\n");

    char *bitcoin_address = "bc1q0cgzunwtnydaklsrrv8gc6frdm9tq2fdprydl6";
    insert_address.id = 0;
    insert_address.value_size = strlen(bitcoin_address)*sizeof(char); 
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
    
    printf("Bitcoin address: %s on index: %u\n", bitcoin_adress_rec, recover_address.id);
    
    exit(EXIT_SUCCESS);	
}
