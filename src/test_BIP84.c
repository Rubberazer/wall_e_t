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
    gcry_error_t err = 0;    

    /********************
    *  m'/84'/0'/0'/0   *
    *********************/

    mnemonic_t *mnem = NULL;
    key_pair_t *child_keys = NULL;
    key_address_t *keys_address = NULL;
    char *bech32_address = NULL; 
    char *WIF_address = NULL; 
    
    if (!libgcrypt_initializer()) {
	exit(EXIT_FAILURE);
    }

    mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
    if (mnem == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    child_keys = (key_pair_t *)gcry_calloc_secure(6, sizeof(key_pair_t));
    if (child_keys == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    keys_address = (key_address_t *)gcry_calloc_secure(5, sizeof(key_address_t));
    if (keys_address == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    bech32_address = (char *)gcry_calloc_secure(1, 64*sizeof(char));
    if (bech32_address == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    WIF_address = (char *)gcry_calloc_secure(1, 53*sizeof(char));
    if (WIF_address == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
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
	printf("Problem deriving purpose keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Coin: Bitcoin
    err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
    if (err) {
	printf("Problem deriving coin keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Account keys
    err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
    if (err) {
	printf("Problem deriving account keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }	
    // Receive keys index = 0
    err = key_deriv(&child_keys[3], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 0, normal_child);
    if (err) {
	printf("Problem deriving receive keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // Change keys index = 1
    err = key_deriv(&child_keys[4], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 1, normal_child);
    if (err) {
	printf("Problem deriving change keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // First bitcoin keys index = 0
    err = key_deriv(&child_keys[5], (uint8_t *)(&child_keys[3].key_priv), (uint8_t *)(&child_keys[3].chain_code), 0, normal_child);
    if (err) {
	printf("Problem deriving receive keys, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
    }

    // keys addresses
    // Root addresses
    err = ext_keys_address(&keys_address[0], &mnem->keys, NULL, 0, 0, wBIP84);
    if (err) {
	printf("Problem creating address from root keys, %s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // Account addresses
    err = ext_keys_address(&keys_address[1], &child_keys[2], (uint8_t *)(&child_keys[1].key_pub_comp), 3, HARD_KEY_IDX+ACCOUNT, wBIP84);
    if (err) {
	printf("Problem creating address from account keys, %s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // Receive address index = 0
    err = ext_keys_address(&keys_address[2], &child_keys[3], (uint8_t *)(&child_keys[2].key_pub_comp), 4, 0, wBIP84);
    if (err) {
	printf("Problem creating address from receive keys, %s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // Change addresses index = 1
    err = ext_keys_address(&keys_address[3], &child_keys[4], (uint8_t *)(&child_keys[2].key_pub_comp), 4, 1, wBIP84);
    if (err) {
	printf("Problem creating address from change keys, %s, %s", gcry_strerror(err), gcry_strsource(err));
    }
    // First bitcoin address
    err = bech32_encode(bech32_address, 64, (uint8_t *)(&child_keys[5].key_pub_comp), 33, bech32);
    if (err) {
	printf("Problem creating bech32 address from public key, error code:%d", err);
    }

    err = WIF_encode(WIF_address, 52, (uint8_t *)(&child_keys[5].key_priv), mainnet);
    if (err) {
	printf("Problem encoding private key into WIF format, error code:%d", err);
    }
        
    printf("\nMnemonic list: %s\n", mnem->mnemonic);
    printf("Printing seed: \n");
    for (uint32_t i = 0; i < 64; i++) {
	printf("%02x",mnem->seed[i]);
    }
    printf("\nPrinting private root key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",mnem->keys.key_priv[i]);
    }
    printf("\nPrinting root compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x",mnem->keys.key_pub_comp[i]);
    }
    printf("\nPrinting root chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",mnem->keys.chain_code[i]);
    }
    printf("\nPrinting root key_index: %u \n", mnem->keys.key_index);
    printf("\nPrinting purpose private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[0].key_priv[i]);
    }
    printf("\nPrinting purpose compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[0].key_pub_comp[i]);
    }
    printf("\nPrinting purpose chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[0].chain_code[i]);
    }
    printf("\nPrinting purpose key_index: %u \n", child_keys[0].key_index);
    printf("\nPrinting coin private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[1].key_priv[i]);
    }
    printf("\nPrinting coin compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[1].key_pub_comp[i]);
    }
    printf("\nPrinting coin chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[1].chain_code[i]);
    }
    printf("\nPrinting coin key_index: %u \n", child_keys[1].key_index);
    printf("\nPrinting account private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[2].key_priv[i]);
    }
    printf("\nPrinting account compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[2].key_pub_comp[i]);
    }
    printf("\nPrinting account chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[2].chain_code[i]);
    }
    printf("\nPrinting account key_index: %u \n", child_keys[2].key_index);
    printf("\nPrinting receive private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[3].key_priv[i]);
    }
    printf("\nPrinting receive compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[3].key_pub_comp[i]);
    }
    printf("\nPrinting receive chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[3].chain_code[i]);
    }
    printf("\nPrinting receive key_index: %u \n", child_keys[3].key_index);
    printf("\nPrinting change private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[4].key_priv[i]);
    }
    printf("\nPrinting change compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[4].key_pub_comp[i]);
    }
    printf("\nPrinting change chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[4].chain_code[i]);
    }
    printf("\nPrinting change key_index: %u \n", child_keys[4].key_index);
    
    printf("\nPrinting key addresses: \n");
    printf("\nPrinting Root key addresses: \n");
    printf("%s\n", keys_address[0].xpriv);    
    printf("%s\n", keys_address[0].xpub);
    printf("\nPrinting Account key addresses: \n");
    printf("%s\n", keys_address[1].xpriv);
    printf("%s\n", keys_address[1].xpub);
    printf("\nPrinting Receive (BIP32) key addresses: \n");
    printf("%s\n", keys_address[2].xpriv);
    printf("%s\n", keys_address[2].xpub);
    printf("\nPrinting Change key addresses: \n");
    printf("%s\n", keys_address[3].xpriv);
    printf("%s\n", keys_address[3].xpub);
    printf("\n");

    printf("\nPrinting first bitcoin private key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", child_keys[5].key_priv[i]);
    }
    printf("\nPrinting first bitcoin compressed public key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", child_keys[5].key_pub_comp[i]);
    }
    printf("\nPrinting first bitcoin chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x",child_keys[5].chain_code[i]);
    }
    
    printf("\nPrinting change key_index: %u \n", child_keys[5].key_index);
    printf("\nBech32 address of children public key:\n%s\n", bech32_address);
    printf("\nWIF address of first bitcoin private key:\n%s\n", WIF_address);
    
    gcry_free(keys_address);
 allocerr3:
    gcry_free(child_keys);
 allocerr2:
    gcry_free(mnem);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);

    exit(EXIT_SUCCESS);
}
