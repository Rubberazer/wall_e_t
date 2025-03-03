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
#include <wall_e_t.h>

int main(void) {
    static gcry_error_t err = 0;
    mnemonic_t *mnem = NULL;
    key_pair_t *child_keypair = NULL;
    key_address_t *key_address = NULL;
    char *bech32_address = NULL; 
    ECDSA_sign_t *signature = NULL;
    
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
    bech32_address  = (char *)gcry_calloc_secure(64, sizeof(char));
    if (key_address == NULL)
	exit(EXIT_FAILURE);
    signature = (ECDSA_sign_t *)gcry_calloc_secure(1, sizeof(ECDSA_sign_t));
    if (signature == NULL)
	exit(EXIT_FAILURE);
	
    err = create_mnemonic("", 24, mnem);
    if (err) {
	printf("Problem creating mnemonic, error code:%s, %s", gcry_strerror(err), gcry_strsource(err));
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

    err = ext_keys_address(key_address, &mnem->keys, NULL, 0, 0, wBIP84);
    if (err) {
	printf("Problem creating address from keys, error code:%d", err);
    }

    printf("\nPrinting master private key address: \n");
    printf("%s", key_address->xpriv);
    printf("\tAddress length: %lu", strlen(key_address->xpriv));
    printf("\nPrinting master public key address: \n");
    printf("%s", key_address->xpub);
    printf("\tAddress length: %lu", strlen(key_address->xpriv));

    err = bech32_encode(bech32_address, 64, child_keypair->key_pub_comp, 33, bech32);
    if (err) {
	printf("Problem creating address from public key, error code:%d", err);
    }

    printf("\nBech32 address of children public key:\n%s", bech32_address);

    encoding verification = verify_checksum("bc", bech32_address);
    if (verification != bech32) {
	printf("Bech32 address not valid\n");
    }

    // Encrypting some string
    char *message = "1234567890";
    char encrypted_s[128] = "";
    char decrypted_s[256] = "";

    // PKCS#7 + IV length (12 bytes) + Authentication tag (16 bytes)
    uint32_t s_in_length = 0;
    s_in_length = strlen(message)+16+12;
    
    err = encrypt_AES256((uint8_t *)encrypted_s, (uint8_t *)message, strlen(message), "abc&we45./");
    if (err) {
	printf("Problem encrypting message, with erro: %s", gcry_strerror(err));
    }

    printf("\nEncrypted message: %s\n", encrypted_s);
    printf("\nPrinting encrypted message in hex : \n");
    for (uint32_t i = 0; i < s_in_length; i++) {
	printf("%02x", (uint8_t)encrypted_s[i]);
    }

    err = decrypt_AES256((uint8_t *)decrypted_s, (uint8_t *)encrypted_s, s_in_length, "abc&we45./");
    if (err) {
	printf("Problem decrypting message, with error: %s", gcry_strerror(err));
    }

    printf("\nDecrypted message: %s\n", decrypted_s);
    printf("\nPrinting decrypted message in hex : \n");
    for (uint32_t i = 0; i < s_in_length-12-16; i++) {
	printf("%02x", (uint8_t)decrypted_s[i]);
    }

    const char *sign_data = "aaaaxxxxsasasa";
    uint8_t data_hash[32] = {0};
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, data_hash, sign_data, strlen(sign_data));
    printf("\nPrinting hash: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", data_hash[i]);
    }
        
    err = sign_ECDSA(signature, (uint8_t *)sign_data, strlen(sign_data), child_keypair->key_priv);
    if (err) {
	printf("Problem creating signature, error code:%d", err);
    }

    printf("\nPrinting signature parameter r: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", signature->r[i]);
    }
    printf("\nPrinting signature parameter s: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", signature->s[i]);
    }

    printf("\nPrinting DER encoded signature: \n");
    for (uint32_t i = 0; i < 71; i++) {
	printf("%02x", signature->DER_u[i]);
    }
    printf("\nPrinting DER encoded signature in string format: \n%s \n",signature->DER);
    printf("Signature length: %u \n",signature->DER_len);
    
    char mnemonic_test[1000];
    printf("\nOriginal mnemonic: %s\n", mnem->mnemonic);
    strcpy(mnemonic_test, mnem->mnemonic);
    memset(mnem, 0, sizeof(mnemonic_t));
    
    err = recover_from_mnemonic(mnemonic_test, "", mnem);
    if (err) {
	printf("Problem recovering wallet from mnemonic, error code:%s & error source:%s", gcry_strerror(err), gcry_strsource(err));
    }
    printf("\nPrinting recovered seed: \n");
    for (uint32_t i = 0; i < 64; i++) {
	printf("%02x", mnem->seed[i]);
    }
    printf("\nPrinting recovered master key: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", mnem->keys.key_priv[i]);
    }
    printf("\nPrinting recovered master chain code: \n");
    for (uint32_t i = 0; i < 32; i++) {
	printf("%02x", mnem->keys.chain_code[i]);
    }
    printf("\nPrinting recovered compressed public master key: \n");
    for (uint32_t i = 0; i < 33; i++) {
	printf("%02x", mnem->keys.key_pub_comp[i]);
    }

    char *test_base58 = "32XxrQVA9Fuyi9xDyiA6kysacd8p5wdPDq";
    uint8_t test_decode58[25] = {0};
    err = base58_decode(test_decode58, 25, test_base58, strlen(test_base58));
    if (err) {
	printf("Problem decoding base58 address, error code:%s & error source:%s", gcry_strerror(err), gcry_strsource(err));
    }

    printf("\nPrinting original base 58:\n%s \n", test_base58);
    printf("Printing decoded base 58: \n");
    for (uint32_t i = 0; i < 25; i++) {
	printf("%02x", test_decode58[i]);
    }

    char *test_base32 = "qw09xhr72fs5270uh4lcnzh2dwprrqlk0"; // bc1qw09xhr72fs5270uh4lcnzh2dwprrqlk0evptcs
    uint8_t test_decode32[22] = {0};
    err = base32_decode(test_decode32, 22, test_base32, strlen(test_base32)) ;
    if (err) {
	printf("Problem decoding base32 address, error code:%s & error source:%s", gcry_strerror(err), gcry_strsource(err));
    }

    printf("\nPrinting original base 32:\n%s \n", test_base32);
    printf("Printing decoded base 32: \n");
    for (uint32_t i = 0; i < 22; i++) {
	printf("%02x", test_decode32[i]);
    }

    gcry_free(signature);
    gcry_free(bech32_address);
    gcry_free(key_address);
    gcry_free(child_keypair);
    gcry_free(mnem);
	
    gcry_control(GCRYCTL_TERM_SECMEM); // IMPORTANT IF NOT EXPECT ALL SORTS OF MESSED UP STUFF AS THE MEMORY VAULT LINGERS AROUND

    printf("\nExiting out\n");
    exit(EXIT_SUCCESS);
}
