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
#include <wall_e_t.h>

int main(void) {
    static gcry_error_t err = 0;    

    // m'/84'/0'/0'/0

    mnemonic_t *mnem = NULL;
    key_pair_t *purpose_keys = NULL;
    key_pair_t *coin_keys = NULL;
    key_pair_t *account_keys = NULL;
    key_pair_t *receive_keys = NULL;
    key_pair_t *change_keys = NULL;
    key_address_t *root_address = NULL;
    key_address_t *account_address = NULL; 
    
    if (!libgcrypt_initializer()) {
	exit(EXIT_FAILURE);
    }

    mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
    if (mnem == NULL)
	exit(EXIT_FAILURE);
    
    
    
    gcry_free(change_keys);
    gcry_free(receive_keys);
    gcry_free(account_keys);
    gcry_free(coin_keys);
    gcry_free(purpose_keys);
    gcry_free(mnem);
	
    gcry_control(GCRYCTL_TERM_SECMEM);

    printf("\nExiting out\n");
    exit(EXIT_SUCCESS);
}
