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

int main(void) {
    static gcry_error_t err = 0;    

    /********************
    *  m'/84'/0'/0'/0   *
    *********************/

    mnemonic_t *mnem = NULL;
    key_pair_t *child_keys = NULL;
    //key_address_t *root_address = NULL;
    //key_address_t *account_address = NULL; 
    
    if (!libgcrypt_initializer()) {
	exit(EXIT_FAILURE);
    }

    mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
    if (mnem == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    child_keys = (key_pair_t *)gcry_calloc_secure(5, sizeof(key_pair_t));
    if (child_keys == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }

    // Obtain mnemonic + root keys
    err = create_mnemonic("xxxx", 12, mnem);
    if (err) {
	printf("Problem creating mnemonic, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // Deriving keys
    // Purpose: BIP84
    err = key_deriv(&child_keys[0], mnem->keys.key_priv, mnem->keys.chain_code, BIP84, hardened_child);
    if (err) {
	printf("Problem deriving child key, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Coin: Bitcoin
    err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
    if (err) {
	printf("Problem deriving child key, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Account keys
    err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
    if (err) {
	printf("Problem deriving child key, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Receive keys
    err = key_deriv(&child_keys[3], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 0, normal_child);
    if (err) {
	printf("Problem deriving child key, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Change keys
    err = key_deriv(&child_keys[4], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 1, normal_child);
    if (err) {
	printf("Problem deriving child key, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    printf("\nMnemonic list: %s\n", mnem->mnemonic);
    printf("\nPrinting private root key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",mnem->keys.key_priv[i]);
    }
    printf("\nPrinting root compressed public key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",mnem->keys.key_pub_comp[i]);
    }
    printf("\nPrinting account private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[2].key_priv[i]);
    }
    printf("\nPrinting account compressed public key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[2].key_pub_comp[i]);
    }
    printf("\n");
    
    gcry_free(child_keys);
 allocerr2:
    gcry_free(mnem);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);

    exit(EXIT_SUCCESS);
}
