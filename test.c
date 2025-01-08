/* Bitcoin wallet on the command line based on the libgcrypt library
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
#include <wall_e_t.h>

int main(void) {
	static gcry_error_t err = 0;
	mnemonic_t *mnem = NULL;
   	key_pair_t *child_keypair = NULL;
	key_address_t *key_address = NULL;
			
	if (!libgcrypt_initializer()) {
		exit(EXIT_FAILURE);
	}

	mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
	if (mnem == NULL)
		exit(EXIT_FAILURE);
	child_keypair = (key_pair_t *)gcry_calloc_secure(1, sizeof(key_pair_t));
	if (child_keypair == NULL)
		exit(EXIT_FAILURE);
	key_address = (key_address_t *)gcry_calloc_secure(1, sizeof(key_address_t));
	if (key_address == NULL)
		exit(EXIT_FAILURE);
	
	err = create_mnemonic("dasdasds", 24, mnem);
	if (err) {
		printf("Problem creating mnemonic, error code:%d", err);
	}

	printf("\nMnemonic list: %s\n", mnem->mnemonic);
	printf("Printing seed: \n");
	for (uint32_t i = 0; i < 64; i++) {
		printf("%02x",mnem->seed[i]);
	}
	printf("\nPrinting master key+chain code: \n");
	for (uint32_t i = 0; i < 64; i++) {
		printf("%02x",mnem->keys.key_priv_chain[i]);
	}	
	printf("\nPrinting master key: \n");
	for (uint32_t i = 0; i < 32; i++) {
		printf("%02x",mnem->keys.key_priv[i]);
	}
	printf("\nPrinting master chain code: \n");
	for (uint32_t i = 0; i < 32; i++) {
		printf("%02x",mnem->keys.chain_code[i]);
	}
	printf("\nPrinting uncompressed public key: \n");
	for (uint32_t i = 0; i < 65; i++) {
		printf("%02x",mnem->keys.key_pub[i]);
	}	
	printf("\nPrinting compressed public key: \n");
	for (uint32_t i = 0; i < 33; i++) {
		printf("%02x",mnem->keys.key_pub_comp[i]);
	}
	
	err = key_deriv(child_keypair, mnem->keys.key_priv, mnem->keys.chain_code, 0, hardened_child);
	if (err) {
		printf("Problem deriving child key, error code:%d", err);
	}	

	printf("\nPrinting derived child chain code: \n");
	for (uint32_t i = 0; i < 32; i++) {
		printf("%02x", child_keypair->chain_code[i]);
	}

	printf("\nPrinting derived child private key : \n");
	for (uint32_t i = 0; i < 32; i++) {
		printf("%02x", child_keypair->key_priv[i]);
	}

	printf("\nPrinting derived child compressed public key : \n");
	for (uint32_t i = 0; i < 33; i++) {
		printf("%02x", child_keypair->key_pub_comp[i]);
	}

	err = ext_keys_address(key_address, &mnem->keys, NULL, 0, wBIP84);
	if (err) {
		printf("Problem creating address from keys, error code:%d", err);
	}

	printf("\nPrinting master private key address: \n");
	printf("%s", key_address->xpriv);
	printf("Address length: %lu", strlen(key_address->xpriv));
	printf("\nPrinting master private key address: \n");
	printf("%s", key_address->xpub);
	printf("Address length: %lu", strlen(key_address->xpriv));
	
	gcry_free(key_address);
	gcry_free(child_keypair);
	gcry_free(mnem);
	
	gcry_control(GCRYCTL_TERM_SECMEM); // IMPORTANT IF NOT EXPECT ALL SORTS OF MESSED UP STUFF AS THE MEMORY VAULT LINGERS AROUND

	printf("\nExiting out\n");
	exit(EXIT_SUCCESS);
}
