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

gcry_error_t libgcrypt_initializer(void) {
    gcry_error_t err = GPG_ERR_NO_ERROR;

    // Check libgcrypt version	
    const char *version = gcry_check_version(NEED_LIBGCRYPT_VERSION);
    //fprintf(stdout, "libgcrypt version: %s\n", version);
    if (!version) {
	fprintf(stderr, "Libgcrypt is too old (need %s, have %s)\n",
		NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
	exit(EXIT_FAILURE);
    }	
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if (err) {
	fprintf(stderr, "Suspending memory warnings failed, exiting\n");
	exit(EXIT_FAILURE);
    }	
    // Enable secure memory
    err = gcry_control(GCRYCTL_INIT_SECMEM, 5242880, 0);
    if (err) {
	fprintf(stderr, "Secure memory enabling failed, exiting\n");
	exit(EXIT_FAILURE);
    }
    err = gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    if (err) {
	fprintf(stderr, "Enabling memory warnings failed, exiting\n");
	exit(EXIT_FAILURE);
    }	
    // Tell Libgcrypt that initialization is completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err) {
	fprintf(stderr, "Libgcrypt initialization failed, exiting\n");
	exit(EXIT_FAILURE);
    }
    // Verify that initialization is complete
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P);
	
    return err; 
}

gcry_error_t char_to_uint8(char *s_string, uint8_t *s_number, size_t string_length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    char *string_swap = NULL;

    if (s_string == NULL || string_length < 1) {
	fprintf (stderr, "s_string can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (s_number == NULL) {
	fprintf(stderr, "s_number can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	

    string_swap = (char *)gcry_calloc_secure(5, sizeof(char));
    if (string_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }

    for (uint32_t i = 0, j = 0; i < string_length; i += 2, j++) {
	sprintf(string_swap, "%c%c", s_string[i], s_string[i+1]);
	s_number[j] = (uint8_t)strtoul(string_swap, NULL, 16);
    }

    gcry_free(string_swap);
 allocerr1:
	
    return err;
}

gcry_error_t uint8_to_char(uint8_t *s_number, char *s_string, size_t uint8_length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    char *string_swap = NULL;
    
    if (s_number == NULL || uint8_length < 1) {
	fprintf (stderr, "s_number can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (s_string == NULL) {
	fprintf(stderr, "s_string can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	

    string_swap = (char *)gcry_calloc_secure(5, sizeof(char));
    if (string_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }

    for (uint32_t i = 0; i < uint8_length; i++) {
	sprintf(string_swap, "%02x", s_number[i]);
	strcat(s_string, string_swap);
    }

    gcry_free(string_swap);
 allocerr1:
	
    return err;
}

gcry_error_t hash_to_hash160(uint8_t *hash160, uint8_t *hex, size_t hex_length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *s_buff = NULL;

    if (hex == NULL || hex_length < 1) {
	fprintf (stderr, "hex can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (hash160 == NULL) {
	fprintf(stderr, "hash160 can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	

    s_buff = (uint8_t *)gcry_calloc_secure(gcry_md_get_algo_dlen(GCRY_MD_SHA256), sizeof(uint8_t));
    if (s_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }	
	
    gcry_md_hash_buffer(GCRY_MD_SHA256, s_buff, hex, hex_length);	
    gcry_md_hash_buffer(GCRY_MD_RMD160, hash160, s_buff, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
						
    gcry_free(s_buff);	
 allocerr1:
    return err;
}			   

gcry_error_t reverse_bytes(uint8_t *output, uint8_t *input, size_t length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;

    if (input == NULL || output == NULL) {
	fprintf (stderr, "input and output can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (length < 2) {
	fprintf (stderr, "length can't be less than 2 bytes\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    
    for (size_t i = 0; i < length; i++) {
	output[i] = input[length-1-i];
    }
    
    return err;
}

gcry_error_t base58_encode(char *base58, size_t char_length, uint8_t *key, size_t uint8_length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    gcry_mpi_t mpi_base58 = NULL;
    gcry_mpi_t mpi_key = NULL;
    gcry_mpi_t mpi_result = NULL;
    gcry_mpi_t mpi_mod = NULL;
    char *string_swap = NULL;
    uint32_t *uint8_swap = NULL;
    char base58_arr[] = BASE58;

    if (key == NULL || uint8_length < 1) {
	fprintf (stderr, "key can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (base58 == NULL) {
	fprintf(stderr, "base58 can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	

    mpi_base58 = gcry_mpi_snew(8);
    if (mpi_base58 == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    mpi_key = gcry_mpi_snew(uint8_length*8);
    if (mpi_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    mpi_result = gcry_mpi_snew(uint8_length*8);
    if (mpi_result == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    mpi_mod = gcry_mpi_snew(8);
    if (mpi_mod == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }
    string_swap = (char *)gcry_calloc_secure(char_length, sizeof(char));
    if (string_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr5;
    }
    uint8_swap = (uint32_t *)gcry_calloc_secure(1, sizeof(uint32_t));
    if (uint8_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr6;
    }

    mpi_base58 = gcry_mpi_set_ui(mpi_base58, 58);
    err = gcry_mpi_scan(&mpi_key, GCRYMPI_FMT_USG, key, uint8_length, NULL);
    if (err) {
	fprintf(stderr, "Failed to scan key to mpi format\n");
	goto allocerr7;
    }
    ssize_t comp = gcry_mpi_cmp_ui(mpi_key, 0);
    if (!comp) {
	fprintf(stderr, "Key is zero\n");
	err = gcry_error_from_errno(EINVAL);
	goto allocerr7;
    }
	
    for (uint32_t i = 0; i < uint8_length; i++) {
	if (key[i] == 0x00) {
	    strcpy(base58+i, "1");
	}
	else
	    break;
    }

    uint32_t counter = 0;
    for (uint32_t i = 0;; i++) {
	gcry_mpi_div(mpi_result, mpi_mod, mpi_key, mpi_base58, -1);
	err = gcry_mpi_get_ui(uint8_swap, mpi_mod);
	if (err) {
	    fprintf(stderr, "Failed operation key mod 58\n");
	    goto allocerr7;
	}
	memcpy(string_swap+char_length-i, &base58_arr[*uint8_swap], 1);	
	mpi_key = gcry_mpi_set(mpi_key, mpi_result);
	if (!gcry_mpi_cmp_ui(mpi_key, 0)) {
	    counter = char_length-i;
	    break;
	}
    }

    strncpy(base58+strlen(base58), string_swap+counter, char_length-strlen(base58));
    	    
 allocerr7:
    gcry_free(uint8_swap);
 allocerr6:
    gcry_free(string_swap);
 allocerr5:
    gcry_mpi_release(mpi_mod);
 allocerr4:
    gcry_mpi_release(mpi_result);
 allocerr3:
    gcry_mpi_release(mpi_key);
 allocerr2:
    gcry_mpi_release(mpi_base58);
 allocerr1:
    return err;
}

gcry_error_t pub_from_priv(uint8_t *pub_key, uint8_t *pub_key_c, uint8_t *priv_key) {
#define BUFF_SIZE 400
    gcry_error_t err = GPG_ERR_NO_ERROR;
    char *s_key_buff = NULL;
    char *s_key_swap = NULL;
    gcry_ctx_t s_key_ctx = NULL;
    gcry_sexp_t s_key_pub = NULL;
    gcry_sexp_t s_key = NULL;	

    s_key_buff = (char *)gcry_calloc_secure(BUFF_SIZE, sizeof(char));
    if (s_key_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }	
    s_key_swap = (char *)gcry_calloc_secure(BUFF_SIZE, sizeof(char));
    if (s_key_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }	

    strcpy(s_key_buff, "(private-key\n (ecc\n  (curve \"secp256k1\")\n  (d #");
    for (uint32_t i = 0; i < 32; i++) {
	sprintf(s_key_swap, "%02X", priv_key[i]);
	strcat(s_key_buff, s_key_swap);
	memset(s_key_swap, 0, strlen(s_key_swap));
    }
    strcat(s_key_buff, "#)))");
	
    // Trying to produce public key from master key
    err = gcry_sexp_new(&s_key, s_key_buff, 0, 1);
    if (err) {
	fprintf(stderr, "Failed to create s-expression for master key\n");
	goto allocerr3;
    }
    err = gcry_mpi_ec_new(&s_key_ctx, s_key, NULL);
    if (err) {
	fprintf(stderr, "Failed to create context type for master key\n");
	goto allocerr4;
    }
    err = gcry_pubkey_get_sexp(&s_key_pub, GCRY_PK_GET_PUBKEY, s_key_ctx);
    if (err) {
	fprintf(stderr, "Failed to extract public key from context\n");
	goto allocerr5;
    }

    memset(s_key_buff, 0, BUFF_SIZE);
    char * P = s_key_buff;
    s_key_pub = gcry_sexp_find_token(s_key_pub, "q", 0);
    gcry_sexp_sprint(s_key_pub, GCRYSEXP_FMT_ADVANCED, s_key_buff, BUFF_SIZE);
    s_key_buff = strtok(s_key_buff, "#");
    s_key_buff = strtok(NULL, "#");

    err = char_to_uint8(s_key_buff, pub_key, strlen(s_key_buff));
    if (err) {
	fprintf(stderr, "Failed to convert public key into a numerical format\n");
    }	
    s_key_buff = P;

    memcpy(pub_key_c, pub_key, PUBKEY_LENGTH);
    // Parity
    pub_key_c[0] = (pub_key[64]%2) ? 0x03 : 0x02;

    gcry_sexp_release(s_key_pub);
 allocerr5:
    gcry_ctx_release(s_key_ctx);    
 allocerr4:
    gcry_sexp_release(s_key);
 allocerr3:
    gcry_free(s_key_swap);	
 allocerr2:
    gcry_free(s_key_buff);	
 allocerr1:

#undef BUFF_SIZE
    return err;
}

gcry_error_t create_mnemonic(char *salt, uint8_t nwords, mnemonic_t *mnem) {
    typedef char *word_t[20];
    gcry_error_t err = GPG_ERR_NO_ERROR;
    char *wordlist[] = {WORDLIST};
    uint32_t nbytes = 0;
    uint8_t *r_seed = NULL;
    uint8_t *h_seed = NULL;
    uint8_t *e_seed = NULL;
    uint32_t *s_swap = NULL;
    word_t *words = NULL;
    char *s_salt = NULL;
    gcry_buffer_t *key_buff = NULL; 	
    
    if (salt == NULL || strlen(salt) > PASSP_MAX-1) {
	fprintf (stderr, "Salt is limited to %d characters in english, no emoticons\n",PASSP_MAX-1);
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (mnem == NULL) {
	fprintf(stderr, "Mnem can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	
	
    switch (nwords) {
    case 12: nbytes = 16; //nbits = 128; 
	break;
    case 15: nbytes = 20; //nbits = 160; 
	break;
    case 18: nbytes = 24; //nbits = 192; 
	break;
    case 21: nbytes = 28; //nbits = 224; 
	break;
    case 24: nbytes = 32; //nbits = 256; 
	break;
    default:
	fprintf (stderr, "Number of words should be either: 12, 15, 18, 21 or 24\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }

    r_seed = (uint8_t *)gcry_calloc_secure(nbytes, sizeof(uint8_t));
    if (r_seed == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    h_seed = (uint8_t *)gcry_calloc_secure(gcry_md_get_algo_dlen(GCRY_MD_SHA256), sizeof(uint8_t));
    if (h_seed == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    e_seed = (uint8_t *)gcry_calloc_secure((nbytes+1), sizeof(uint8_t));
    if (e_seed == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    s_swap = (uint32_t *)gcry_calloc_secure(1, sizeof(uint32_t));
    if (s_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }
    words = (word_t *)gcry_calloc_secure(nwords, sizeof(word_t));
    if (words == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr5;
    }
    s_salt = (char *)gcry_calloc_secure(PASSP_MAX, sizeof(char));
    if (s_salt == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr6;
    }
    key_buff = (gcry_buffer_t *)gcry_calloc_secure(2, sizeof(gcry_buffer_t)+512*sizeof(uint8_t));
    if (key_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr7;
    }	
		
    r_seed = gcry_random_bytes(nbytes, GCRY_VERY_STRONG_RANDOM);
    if (r_seed == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr8;
    }	

    gcry_md_hash_buffer(GCRY_MD_SHA256, h_seed, r_seed, nbytes);	
    memcpy(e_seed+nbytes, h_seed, 1);	
    memcpy(e_seed, r_seed, nbytes);
		
    for (int32_t i = 0, j = 0, k = 0; k < nwords; i++, j++, k++) {
	memcpy(s_swap, e_seed+i, sizeof(uint32_t));
	*s_swap = ((*s_swap << 24) & 0xff000000) | ((*s_swap << 8) & 0x00ff0000) | ((*s_swap >> 8) & 0x0000ff00) | ((*s_swap >> 24) & 0x000000ff);
	*s_swap = *s_swap >> (21-(3*j));
	*s_swap = *s_swap & 0x7ff;
        *words[k] = wordlist[*s_swap];
	if (i == 7 || i == 18 || i == 29) {
	    i = i+3;
	    j = -1;
	}
    }	
	
    for(uint32_t i = 0; i < nwords; i++) {
	strcat(mnem->mnemonic, *words[i]);
	if (i != (nwords-1))
	    strcat(mnem->mnemonic, " ");
    }
    strcpy(s_salt, "mnemonic");
    strcat(s_salt, salt);
    
    err = gcry_kdf_derive(mnem->mnemonic, strlen(mnem->mnemonic), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_salt, strlen(s_salt), PBKDF2_ITERN, gcry_md_get_algo_dlen(GCRY_MD_SHA512), mnem->seed);
    if (err) {
	fprintf(stderr, "Failed to derive seed\n");
	goto allocerr8;
    }

    key_buff[0].len = strlen("Bitcoin seed");
    key_buff[0].data = "Bitcoin seed";
    key_buff[1].len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    key_buff[1].data = mnem->seed;
		
    err = gcry_md_hash_buffers(GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC, mnem->keys.key_priv_chain, key_buff, 2);
    if (err) {
	fprintf(stderr, "Failed to produce master key with chain code\n");
	goto allocerr8;
    }

    memcpy(mnem->keys.key_priv, mnem->keys.key_priv_chain, PRIVKEY_LENGTH);
    memcpy(mnem->keys.chain_code, mnem->keys.key_priv_chain+PRIVKEY_LENGTH, CHAINCODE_LENGTH);

    err = pub_from_priv(mnem->keys.key_pub, mnem->keys.key_pub_comp, mnem->keys.key_priv);
    if (err) {
	fprintf(stderr, "Failed to produce public key from private\n");
	goto allocerr8;
    }
    mnem->keys.key_index = 0x00; 

 allocerr8:
    gcry_free(key_buff);	
 allocerr7:
    gcry_free(s_salt);
 allocerr6:
    gcry_free(words);
 allocerr5:
    gcry_free(s_swap);
 allocerr4:
    gcry_free(e_seed);
 allocerr3:
    gcry_free(h_seed);
 allocerr2:
    gcry_free(r_seed);
 allocerr1:
	
    return err;
}

gcry_error_t recover_from_mnemonic(char *mnemonic, char *salt, mnemonic_t *mnem) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    typedef char word_t[24][50];
    char *wordlist[] = {WORDLIST};
    word_t *words = NULL;
    char *s_salt = NULL;
    char *s_swap = NULL;
    gcry_buffer_t *key_buff = NULL;
    
    if (mnemonic == NULL || strlen(mnemonic) < 1) {
	fprintf(stderr, "mnemonic can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (mnem == NULL) {
	fprintf(stderr, "keys can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (salt == NULL || strlen(salt) > PASSP_MAX-1) {
	fprintf (stderr, "salt is limited to %d characters in english, no emoticons\n", PASSP_MAX-1);
	err = gcry_error_from_errno(EINVAL);
	return err;
    }

    words = (word_t *)gcry_calloc_secure(1, sizeof(word_t));
    if (words == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }	
    s_salt = (char *)gcry_calloc_secure(PASSP_MAX, sizeof(char));
    if (s_salt == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    s_swap = (char *)gcry_calloc_secure(50, sizeof(char));
    if (s_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    key_buff = (gcry_buffer_t *)gcry_calloc_secure(2, sizeof(gcry_buffer_t)+512*sizeof(uint8_t));
    if (key_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }	

    uint32_t i = 0;
    uint32_t j = 0;
    int32_t count = 0;
    while (mnemonic[i] != '\0') {
	while (mnemonic[i] == ' ') {
	    i++;
	}
	while (mnemonic[i] != ' ' && mnemonic[i] != '\0') {
	    s_swap[j] = mnemonic[i];
	    i++, j++;
	}
	strcpy(*words[count], s_swap);
	memset(s_swap, 0, 50);
	j = 0;
	count++;
    }

    if (count != 12 && count != 15 && count != 18 && count != 21 && count != 24) {
	err = gcry_error_from_errno(EINVAL);
	fprintf(stderr, "Number of words in mnemonic phrase is not standard\n");
	goto allocerr5;
    }

    uint32_t match = 0;
    for (uint32_t i = 0; i < count; i++) {
	for (uint32_t j = 0; j < 2048; j++) {
	    if (!strcmp(*words[i], wordlist[j])) {
		match++;
	    }
	}
    }
    if (count != match) {
	err = gcry_error_from_errno(EINVAL);
	fprintf(stderr, "Words not in dictionary, mnemonic is not valid\n");
	goto allocerr5;
    }
    
    strcpy(s_salt, "mnemonic");
    strcat(s_salt, salt);
    
    err = gcry_kdf_derive(mnemonic, strlen(mnemonic), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_salt, strlen(s_salt), PBKDF2_ITERN, gcry_md_get_algo_dlen(GCRY_MD_SHA512), mnem->seed);
    if (err) {
	fprintf(stderr, "Failed to derive seed\n");
	goto allocerr5;
    }

    key_buff[0].len = strlen("Bitcoin seed");
    key_buff[0].data = "Bitcoin seed";
    key_buff[1].len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    key_buff[1].data = mnem->seed;
		
    err = gcry_md_hash_buffers(GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC, mnem->keys.key_priv_chain, key_buff, 2);
    if (err) {
	fprintf(stderr, "Failed to produce master key with chain code\n");
	goto allocerr5;
    }

    memcpy(mnem->keys.key_priv, mnem->keys.key_priv_chain, PRIVKEY_LENGTH);
    memcpy(mnem->keys.chain_code, mnem->keys.key_priv_chain+PRIVKEY_LENGTH, CHAINCODE_LENGTH);

    err = pub_from_priv(mnem->keys.key_pub, mnem->keys.key_pub_comp, mnem->keys.key_priv);
    if (err) {
	fprintf(stderr, "Failed to produce public key from private\n");
	goto allocerr5;
    }
    mnem->keys.key_index = 0x00; 

 allocerr5:
    gcry_free(key_buff);    
 allocerr4:
    gcry_free(s_swap);
 allocerr3:
    gcry_free(s_salt);
 allocerr2:
    gcry_free(words);
 allocerr1:
    
    return err;
}

gcry_error_t key_deriv(key_pair_t *child_keys, uint8_t *parent_priv_key, uint8_t *parent_chain_code, uint32_t key_index, hardened_t hardened) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    gcry_buffer_t *key_buff = NULL;
    uint8_t *swap_priv_key = NULL;
    uint32_t *index = NULL;
    uint8_t *intermediate_key = NULL;
    uint8_t *n_secp256k1 = NULL;
    gcry_mpi_t interm_key = NULL;
    gcry_mpi_t order_sec = NULL;
    gcry_mpi_t key_par = NULL;
    gcry_mpi_t key_child = NULL;
    gcry_mpi_t key_mod_result = NULL;
	
    if (key_index < 0) {
	fprintf(stderr, "Derived key index should be bigger than 0\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (hardened < 0 || hardened > 1) {
	fprintf(stderr, "Hardened should be either \"hardened\" or \"normal\"\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (child_keys == NULL || parent_priv_key == NULL || parent_chain_code == NULL) {
	fprintf(stderr, "Child_keys, parent_priv_key and parent_chain_code can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	
	
    key_buff = (gcry_buffer_t *)gcry_calloc_secure(2, sizeof(gcry_buffer_t)+512*sizeof(uint8_t));
    if (key_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }	
    swap_priv_key = (uint8_t *)gcry_calloc_secure(37, sizeof(uint8_t));
    if (swap_priv_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }		
    index = (uint32_t *)gcry_calloc_secure(1, sizeof(uint32_t));
    if (index == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    intermediate_key = (uint8_t *)gcry_calloc_secure(64, sizeof(uint8_t));
    if (intermediate_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }
    interm_key = gcry_mpi_snew(256);
    if (interm_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr5;
    }
    order_sec = gcry_mpi_snew(256);
    if (order_sec == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr6;
    }
    key_par = gcry_mpi_snew(256);
    if (key_par == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr7;
    }
    key_child = gcry_mpi_snew(256);
    if (key_child == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr8;
    }
    key_mod_result = gcry_mpi_snew(256);
    if (key_mod_result == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr9;
    }
    n_secp256k1 = (uint8_t *)gcry_calloc_secure(32, sizeof(uint8_t));
    if (n_secp256k1 == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr10;
    }
	
    if (hardened == hardened_child) {
	*index = HARD_KEY_IDX+key_index;
    }
    else {
	*index = key_index;
    }
    child_keys->key_index = *index;
    *index = ((*index << 24) & 0xff000000) | ((*index << 8) & 0x00ff0000) | ((*index >> 8) & 0x0000ff00) | ((*index >> 24) & 0x000000ff);

    if (hardened == hardened_child) {
	swap_priv_key[0] = 0x00;
	memcpy(swap_priv_key+1, parent_priv_key, PRIVKEY_LENGTH);
	memcpy(swap_priv_key+PUBKEY_LENGTH, index, sizeof(uint32_t));
	
	key_buff[1].len = 37;
	key_buff[1].data = swap_priv_key;
	key_buff[0].len = CHAINCODE_LENGTH;
	key_buff[0].data = parent_chain_code;
    }
    else {
	key_pair_t *inter_public = (key_pair_t *)gcry_calloc_secure(1, sizeof(key_pair_t));
	if (inter_public == NULL) {
	    err = gcry_error_from_errno(ENOMEM);
	    goto allocerr11;
	}
	err = pub_from_priv(inter_public->key_pub, inter_public->key_pub_comp, parent_priv_key);
	if (err) {
	    fprintf(stderr, "Failed to derive public from private parent key\n");
	}
	memcpy(swap_priv_key, inter_public->key_pub_comp, PUBKEY_LENGTH);
	memcpy(swap_priv_key+PUBKEY_LENGTH, index, sizeof(uint32_t));
	
	key_buff[1].len = 37;
	key_buff[1].data = swap_priv_key;
	key_buff[0].len = CHAINCODE_LENGTH;
	key_buff[0].data = parent_chain_code;

	gcry_free(inter_public);
    }
    
    err = gcry_md_hash_buffers(GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC, intermediate_key, key_buff, 2);
    if (err) {
	fprintf(stderr, "Failed to HMAC child private key\n");
	goto allocerr11;
    }

    memcpy(child_keys->chain_code, intermediate_key+PRIVKEY_LENGTH, CHAINCODE_LENGTH);
    err = gcry_mpi_scan(&interm_key, GCRYMPI_FMT_USG, intermediate_key, CHAINCODE_LENGTH, NULL);
    if (err) {
	fprintf(stderr, "Failed to scan intermediate key to mpi format\n");
	goto allocerr11;
    }
    err = char_to_uint8(N_SECP256K1, n_secp256k1, 64);	
    if (err) {
	fprintf(stderr, "Failed to convert N_SECP256K1 to unsigned char\n");
	goto allocerr11;
    }	
    err = gcry_mpi_scan(&order_sec, GCRYMPI_FMT_USG, n_secp256k1, 32, NULL);
    if (err) {
	fprintf(stderr, "Failed to scan N_SECP256K1 to mpi format\n");
	goto allocerr11;
    }
	
    ssize_t comp = gcry_mpi_cmp(interm_key, order_sec);	
    if (comp > 0) {
	fprintf(stderr, "Child key is invalid, use the next index value\n");
	err = gcry_error_from_errno(EINVAL);
	goto allocerr11;
    }
    comp = gcry_mpi_cmp_ui(interm_key, 0x0);
    if (!comp) {
	fprintf(stderr, "Child key is invalid, use the next index value\n");
	err = gcry_error_from_errno(EINVAL);
	goto allocerr11;
    }

    err = gcry_mpi_scan(&key_par, GCRYMPI_FMT_USG, parent_priv_key, PRIVKEY_LENGTH, NULL);
    if (err) {
	fprintf(stderr, "Failed to scan N_SECP256K1 to mpi format\n");
	goto allocerr11;
    }
    err = gcry_mpi_scan(&key_child, GCRYMPI_FMT_USG, intermediate_key, PRIVKEY_LENGTH, NULL);
    if (err) {
	fprintf(stderr, "Failed to scan N_SECP256K1 to mpi format\n");
	goto allocerr11;
    }	
	
    gcry_mpi_addm(key_mod_result, key_child, key_par, order_sec);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, child_keys->key_priv, PRIVKEY_LENGTH, NULL, key_mod_result); 
    if (err) {
	fprintf(stderr, "Failed to modulo the child private key\n");
	goto allocerr11;
    }
		
    err = pub_from_priv(child_keys->key_pub, child_keys->key_pub_comp, child_keys->key_priv);
    if (err) {
	fprintf(stderr, "Failed to derive child public from private child key\n");
	goto allocerr11;
    }

 allocerr11:
    gcry_free(n_secp256k1);
 allocerr10:
    gcry_mpi_release(key_mod_result);
 allocerr9:
    gcry_mpi_release(key_child);
 allocerr8:
    gcry_mpi_release(key_par);
 allocerr7:
    gcry_mpi_release(order_sec);
 allocerr6:
    gcry_mpi_release(interm_key);
 allocerr5:
    gcry_free(intermediate_key);
 allocerr4:
    gcry_free(index);
 allocerr3:
    gcry_free(swap_priv_key);
 allocerr2:
    gcry_free(key_buff);	
 allocerr1:
	
    return err;
}

gcry_error_t ext_keys_address(key_address_t *keys_address, key_pair_t *keys, uint8_t *par_pub, uint8_t depth, uint32_t key_index, BIP_t wallet_type)  {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *intermediate_key = NULL;
    uint8_t *hash160 = NULL;
    uint8_t *checksum = NULL;
    char *BIP_PRV = NULL;
    char *BIP_PUB = NULL;
	
    if (depth < 0) {
	fprintf(stderr, "Depth should be 0 or higher\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (key_index < 0) {
	fprintf(stderr, "Derived key index should be bigger than 0\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (keys_address == NULL || keys == NULL) {
	fprintf(stderr, "keys_address, keys can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
	
    intermediate_key = (uint8_t *)gcry_calloc_secure(INTER_KEY+CHECKSUM, sizeof(uint8_t));
    if (intermediate_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    hash160 = (uint8_t *)gcry_calloc_secure(HASH160_LENGTH, sizeof(uint8_t));
    if (hash160 == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    checksum = (uint8_t *)gcry_calloc_secure(PRIVKEY_LENGTH, sizeof(uint8_t));
    if (checksum == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }		
    if (depth) {		
	err = hash_to_hash160(hash160, par_pub, PUBKEY_LENGTH);
	if (err) {
	    fprintf(stderr, "Failed to create fingerprint from parent key\n");
	    goto allocerr4;
	}	
    }
    else {
	memset(hash160, 0, HASH160_LENGTH);
    }

    switch (wallet_type) {
    case wBIP32: 
	BIP_PRV = XPRV;
	BIP_PUB = XPUB;
	break;
    case wBIP44: 
	BIP_PRV = YPRV;
	BIP_PUB = YPUB;
	break;
    case wBIP84: 
	BIP_PRV = ZPRV;
	BIP_PUB = ZPUB;
	break;
    default:
	BIP_PRV = ZPRV;
	BIP_PUB = ZPUB;		
    }
    
    key_index = ((key_index << 24) & 0xff000000) | ((key_index << 8) & 0x00ff0000) | ((key_index >> 8) & 0x0000ff00) | ((key_index >> 24) & 0x000000ff);
    memcpy(intermediate_key+4, &depth, 1);
    memcpy(intermediate_key+5, hash160, 4);
    memcpy(intermediate_key+9, &key_index, sizeof(uint32_t));
		
    //Private key	
    err = char_to_uint8(BIP_PRV, intermediate_key, 8);
    if (err) {
	fprintf(stderr, "Failed to convert intermediate key to numerical format\n");
	goto allocerr4;
    }	
    memcpy(intermediate_key+13, keys->chain_code, CHAINCODE_LENGTH);
    memset(intermediate_key+45, 0, 1);
    memcpy(intermediate_key+46, keys->key_priv, PRIVKEY_LENGTH);
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, intermediate_key, INTER_KEY);
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, checksum, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    memcpy(intermediate_key+INTER_KEY, checksum, CHECKSUM);
	
    // Here private address
    err = base58_encode(keys_address->xpriv, sizeof(keys_address->xpriv)/sizeof(char), intermediate_key, INTER_KEY+CHECKSUM);
    if (err) {
	fprintf(stderr, "Failed to convert intermediate priv key to address format\n");
	goto allocerr4;
    }

    //Public key
    memset(checksum, 0, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    err = char_to_uint8(BIP_PUB, intermediate_key, 8);
    if (err) {
	fprintf(stderr, "Failed to convert intermediate key to numerical format\n");
	goto allocerr4;
    }	
    memcpy(intermediate_key+13, keys->chain_code, CHAINCODE_LENGTH);
    memcpy(intermediate_key+45, keys->key_pub_comp, PUBKEY_LENGTH);
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, intermediate_key, INTER_KEY);
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, checksum, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    memcpy(intermediate_key+INTER_KEY, checksum, CHECKSUM);
	
    // Here public address	
    err = base58_encode(keys_address->xpub, sizeof(keys_address->xpub)/sizeof(char), intermediate_key, INTER_KEY+CHECKSUM);
    if (err) {
	fprintf(stderr, "Failed to convert intermediate pub key to address format\n");
	goto allocerr4;
    }

 allocerr4:
    gcry_free(checksum);
 allocerr3:
    gcry_free(hash160);	
 allocerr2:
    gcry_free(intermediate_key);	
 allocerr1:
    return err;
}

gcry_error_t bech32_encode(char *bech32_address, size_t char_length, uint8_t *key, size_t uint8_length, encoding bech_type) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *intermediate_key = NULL;
    uint8_t *intermediate_hash = NULL;
    uint64_t *s_swap = NULL;
    uint8_t *checksum = NULL;
    char fiver[] = BECH32;
    char  *hrp_code = NULL;

    if (bech_type != bech32) {
	fprintf(stderr, "encoding *bech32 only accepted value is: bech32\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    else {
	hrp_code = "bc";
    }
    if (bech32_address == NULL || key == NULL) {
	fprintf(stderr, "bech32_address and key pointers can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
       
    const uint32_t intermediate_key_len = ((HASH160_LENGTH*8)%5) ? (HASH160_LENGTH*8/5)+8 : (HASH160_LENGTH*8/5)+7;
	
    intermediate_key = (uint8_t *)gcry_calloc_secure(intermediate_key_len, sizeof(uint8_t));
    if (intermediate_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    intermediate_hash = (uint8_t *)gcry_calloc_secure(HASH160_LENGTH, sizeof(uint8_t));
    if (intermediate_hash == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    s_swap = (uint64_t *)gcry_calloc_secure(1, sizeof(uint64_t));
    if (s_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    checksum = (uint8_t *)gcry_calloc_secure(6, sizeof(uint8_t));
    if (checksum == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }	
	
    err = hash_to_hash160(intermediate_hash, key, uint8_length);

    intermediate_key[0] = 0x00; 
    for (int32_t i = 0, j = 0, k = 1; k < intermediate_key_len; j++, k++) {
	memcpy(s_swap, intermediate_hash+i, sizeof(uint64_t));
	*s_swap = ((*s_swap << 56) & 0xff00000000000000) | ((*s_swap << 40) & 0x00ff000000000000) | ((*s_swap << 24) & 0x0000ff0000000000) | ((*s_swap << 8) & 0x000000ff00000000) |
	    ((*s_swap >> 8) & 0x00000000ff000000) | ((*s_swap >> 24) & 0x0000000000ff0000) | ((*s_swap >>40) & 0x000000000000ff00) | ((*s_swap >> 56) & 0x00000000000000ff);
	*s_swap = *s_swap >> (59-(5*j));
	*s_swap = *s_swap & 0x1f;
	intermediate_key[k] = *s_swap;
	if (!((j+1)%8)) {
	    i += 5;
	    j = -1;
	}
	if (i > 15) break;
    }
	
    err = create_checksum(hrp_code, intermediate_key, intermediate_key_len, bech32, checksum);
    if (err) {
	fprintf(stderr, "Failed to create bech32 checksum\n");
	goto allocerr5;
    }
    memcpy(intermediate_key+(intermediate_key_len-6), checksum, 6);

    strcpy(bech32_address, "bc1");
    for (size_t i = 0, j = 3; i < intermediate_key_len; i++, j++) {
	bech32_address[j] = fiver[intermediate_key[i]];
    }
    
    encoding verification = verify_checksum(hrp_code, bech32_address);
    if (verification != bech32) {
	fprintf(stderr, "Bech32 address not valid\n");
    }
    
 allocerr5:
    gcry_free(checksum);
 allocerr4:
    gcry_free(s_swap);
 allocerr3:
    gcry_free(intermediate_hash);	
 allocerr2:
    gcry_free(intermediate_key);	
 allocerr1:
    return err;
}

gcry_error_t WIF_encode(char *WIF, size_t char_length, uint8_t *priv_key, net_t bitcoin_net) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *s_buff = NULL;
    uint8_t *checksum = NULL;
    
    if (WIF == NULL || char_length < 52) {
	fprintf(stderr, "WIF string can't be NULL or less than 52 characters length\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (priv_key == NULL) {
	fprintf(stderr, "priv_key can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }

    s_buff = (uint8_t *)gcry_calloc_secure(38, sizeof(uint8_t));
    if (s_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    checksum = (uint8_t *)gcry_calloc_secure(32, sizeof(uint8_t));
    if (checksum == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }

    switch (bitcoin_net) {
    case mainnet: s_buff[0] = 0x80;
	break;
    case testnet: s_buff[0] = 0xef;
	break;
    default:
	fprintf(stderr, "bitcoin_net should be either: mainnet or testnet\n");
	err = gcry_error_from_errno(EINVAL);
	goto allocerr2;
    }
    
    memcpy(s_buff+1, priv_key, PRIVKEY_LENGTH);
    s_buff[33] = 0x01;
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, s_buff, PRIVKEY_LENGTH+2);
    gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, checksum, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    memcpy(s_buff+34, checksum, CHECKSUM);
    
    err = base58_encode(WIF, char_length, s_buff, 38);
    if (err) {
	fprintf(stderr, "Failed to convert intermediate priv key to base58 format\n");
	goto allocerr2;
    }
    
    gcry_free(checksum);
 allocerr2:
    gcry_free(s_buff);
 allocerr1:
    return err;
}

gcry_error_t encrypt_AES256(uint8_t *out, uint8_t *in, size_t in_length, char *password) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *IV = NULL;
    gcry_cipher_hd_t hd;
    uint8_t *s_key = NULL;
    char *s_input = NULL;
    char *s_output = NULL;
    uint32_t s_in_length = 0;
        
    if (password == NULL || strlen(password) < 1) {
	fprintf(stderr, "password can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (in == NULL || out == NULL) {
	fprintf(stderr, "input and output buffers can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    
    if (in_length < 1) {
	fprintf(stderr, "input length can't be 0\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    // PKCS#7
    if (!(in_length%16)) {
	s_in_length = in_length+16;
    }
    else {
	s_in_length = in_length+(16-(in_length%16));
    }
    
    IV = (uint8_t *)gcry_calloc_secure(16, sizeof(uint8_t));
    if (IV == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }	
    s_key = (uint8_t *)gcry_calloc_secure(32, sizeof(uint8_t));
    if (s_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }	
    s_input = (char *)gcry_calloc_secure(s_in_length, sizeof(uint8_t));
    if (s_input == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    s_output = (char *)gcry_calloc_secure(s_in_length, sizeof(uint8_t));
    if (s_output == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }	    

    memcpy(s_input, in, in_length);
    memset(s_input+in_length, (16-(in_length%16)), s_in_length-in_length);

    gcry_create_nonce(IV, 16);
    
    err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (err) {
	fprintf(stderr, "Failed to create context handle\n");
	goto allocerr5;
    }
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, "Archibald Tuttle", strlen("Archibald Tuttle"), PBKDF2_PASS, gcry_md_get_algo_dlen(GCRY_MD_SHA256), s_key);
    if (err) {
	fprintf(stderr, "Failed to derive key from password\n");
	goto allocerr6;
    }
        
    err = gcry_cipher_setkey(hd, s_key, 32);
    if (err) {
	fprintf(stderr, "Failed to set key into context handle\n");
	goto allocerr6;
    }
    err = gcry_cipher_setiv(hd, IV, 16);
    if (err) {
	fprintf(stderr, "Failed to set IV into context handle\n");
	goto allocerr6;
    }
    
    err = gcry_cipher_encrypt(hd, s_output, s_in_length, s_input, s_in_length);
    if (err) {
	fprintf(stderr, "Failed to encrypt\n");
	goto allocerr6;
    }
   
    memcpy(out, s_output, s_in_length);
    memcpy(out+s_in_length, IV, 16);
    
 allocerr6:
    gcry_cipher_close(hd);
 allocerr5:
    gcry_free(s_output);
 allocerr4:
    gcry_free(s_input);
 allocerr3:
    gcry_free(s_key);
 allocerr2:
    gcry_free(IV);	
 allocerr1:
    return err;
}			  

gcry_error_t decrypt_AES256(uint8_t *out, uint8_t *in, size_t in_length, char *password)  {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *IV = NULL;
    gcry_cipher_hd_t hd;
    uint8_t *s_key = NULL;
    char *s_output = NULL;
    char *s_input = NULL;
    
    if (password == NULL || strlen(password) < 1) {
	fprintf(stderr, "password can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (in == NULL || out == NULL) {
	fprintf(stderr, "input and output buffers can't be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (in_length < 1) {
	fprintf(stderr, "input length can't be 0\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }    
    
    IV = (uint8_t *)gcry_calloc_secure(16, sizeof(uint8_t));
    if (IV == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    s_key = (uint8_t *)gcry_calloc_secure(32, sizeof(uint8_t));
    if (s_key == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    s_input = (char *)gcry_calloc_secure(in_length-16, sizeof(uint8_t));
    if (s_input == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }	    
    s_output = (char *)gcry_calloc_secure(in_length-16, sizeof(uint8_t));
    if (s_output == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }	    

    err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (err) {
	fprintf(stderr, "Failed to create context handle\n");
	goto allocerr5;
    }
    
    memcpy(IV, in+(in_length-16), 16);
    memcpy(s_input, in, in_length-16);
    
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, "Archibald Tuttle", strlen("Archibald Tuttle"), PBKDF2_PASS, gcry_md_get_algo_dlen(GCRY_MD_SHA256), s_key);
    if (err) {
	fprintf(stderr, "Failed to derive key from password\n");
	goto allocerr6;
    }
       
    err = gcry_cipher_setkey(hd, s_key, 32);
    if (err) {
	fprintf(stderr, "Failed to set key into context handle\n");
	goto allocerr6;
    }
    err = gcry_cipher_setiv(hd, IV, 16);
    if (err) {
	fprintf(stderr, "Failed to set IV into context handle\n");
	goto allocerr6;
    }

    err = gcry_cipher_decrypt(hd, s_output, in_length-16, s_input, in_length-16);
    if (err) {
	fprintf(stderr, "Failed to decrypt\n");
	goto allocerr6;
    }
    
    memcpy(out, s_output, in_length-16);
   
 allocerr6:
    gcry_cipher_close(hd);
 allocerr5:
    gcry_free(s_output);
 allocerr4:
    gcry_free(s_input);
 allocerr3:
    gcry_free(s_key);	
 allocerr2:
    gcry_free(IV);	
 allocerr1:
    return err;
}

gcry_error_t sign_ECDSA(ECDSA_sign_t *sign, uint8_t *data_in, size_t data_length, uint8_t *priv_key) {
#define BUFF_SIZE 400
    gcry_error_t err = GPG_ERR_NO_ERROR;
    char *s_key_buff = NULL;
    char *s_data_buff = NULL;
    char *s_key_swap = NULL;
    gcry_sexp_t s_key = NULL;
    gcry_sexp_t s_data = NULL;
    gcry_sexp_t s_sign = NULL;	
    uint8_t *data_hash = NULL;
    gcry_ctx_t s_key_ctx = NULL;
    gcry_sexp_t s_key_pub = NULL;
    
    if (sign == NULL || data_in == NULL || priv_key == NULL) {
	fprintf(stderr, "sign, data_in and priv_key can't NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (data_length < 1) {
	fprintf(stderr, "data length can't be 0\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }    

    s_key_buff = (char *)gcry_calloc_secure(BUFF_SIZE, sizeof(char));
    if (s_key_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    s_data_buff = (char *)gcry_calloc_secure(BUFF_SIZE, sizeof(char));
    if (s_data_buff == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }	    
    s_key_swap = (char *)gcry_calloc_secure(BUFF_SIZE, sizeof(char));
    if (s_key_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }	
    s_sign = (gcry_sexp_t)gcry_calloc_secure(1, sizeof(gcry_sexp_t)+512*sizeof(char));
    if (s_sign == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }
    data_hash = (uint8_t *)gcry_calloc_secure(gcry_md_get_algo_dlen(GCRY_MD_SHA256), sizeof(uint8_t));
    if (data_hash == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr5;
    }	
    
    strcpy(s_key_buff, "(private-key\n (ecc\n  (curve \"secp256k1\")\n  (d #");
    for (uint32_t i = 0; i < 32; i++) {
	sprintf(s_key_swap, "%02X", priv_key[i]);
	strcat(s_key_buff, s_key_swap);
	memset(s_key_swap, 0, strlen(s_key_swap));
    }
    strcat(s_key_buff, "#)))");
    err = gcry_sexp_new(&s_key, s_key_buff, 0, 1);
    if (err) {
	fprintf(stderr, "Failed to create s-expression for private key\n");
	goto allocerr6;
    }

    gcry_md_hash_buffer(GCRY_MD_SHA256, data_hash, data_in, data_length);
    memset(s_key_swap, 0, BUFF_SIZE);
    strcpy(s_data_buff, "(data\n (flags raw)\n  (value #");
    for (uint32_t i = 0; i < 32; i++) {
	sprintf(s_key_swap, "%02X", data_hash[i]);
	strcat(s_data_buff, s_key_swap);
	memset(s_key_swap, 0, strlen(s_key_swap));
    }
    strcat(s_data_buff, "#))");    
    err = gcry_sexp_new(&s_data, s_data_buff, strlen(s_data_buff), 0);
    if (err) {
	fprintf(stderr, "Failed to create s-expression from data\n");
	goto allocerr7;
    }    
    
    err = gcry_pk_sign(&s_sign, s_data, s_key);
    if (err) {
	fprintf(stderr, "Failed to sign data\n");
	goto allocerr8;
    }

    // Verify signature
    err = gcry_mpi_ec_new(&s_key_ctx, s_key, NULL);
    if (err) {
	fprintf(stderr, "Failed to create context type for master key\n");
	goto allocerr8;
    }
    err = gcry_pubkey_get_sexp(&s_key_pub, GCRY_PK_GET_PUBKEY, s_key_ctx);
    if (err) {
	fprintf(stderr, "Failed to extract public key from context\n");
	goto allocerr9;
    }
    err = gcry_pk_verify(s_sign, s_data, s_key_pub);
    if (err) {
	fprintf(stderr, "Signature verification failed\n");
	goto allocerr10;
    }
    
    memset(s_key_swap, 0, BUFF_SIZE);
    char * P = s_key_swap;
    s_data = gcry_sexp_find_token(s_sign, "r", 0);
    gcry_sexp_sprint(s_data, GCRYSEXP_FMT_ADVANCED, s_key_swap, BUFF_SIZE);
    s_key_swap = strtok(s_key_swap, "#");
    s_key_swap = strtok(NULL, "#");
    err = char_to_uint8(s_key_swap, sign->r, strlen(s_key_swap));
    if (err) {
	fprintf(stderr, "Failed to convert signature r value  into a numerical format\n");
    }	
    s_key_swap = P;
    	
    memset(s_key_swap, 0, BUFF_SIZE);
    s_data = gcry_sexp_find_token(s_sign, "s", 0);
    gcry_sexp_sprint(s_data, GCRYSEXP_FMT_ADVANCED, s_key_swap, BUFF_SIZE);
    s_key_swap = strtok(s_key_swap, "#");
    s_key_swap = strtok(NULL, "#");
    err = char_to_uint8(s_key_swap, sign->s, strlen(s_key_swap));
    if (err) {
	fprintf(stderr, "Failed to convert signature s into a numerical format\n");
    }	
    s_key_swap = P;

    // DER Encoding
    size_t DER_len = 0;
    if (sign->r[0] > 0x80) {
	sign->DER_u[0] = 0x30;
	sign->DER_u[1] = 0x45;
	sign->DER_u[2] = 0x02;
	sign->DER_u[3] = 0x21;
	sign->DER_u[4] = 0x00;
	sign->DER_u[37] = 0x02;
	sign->DER_u[38] = 0x20;
	for (size_t i = 0; i < 32; i++) {
	    sign->DER_u[5+i] = sign->r[i];
	    sign->DER_u[39+i] = sign->s[i];
	}
	DER_len = 71;
    }
    else {
	sign->DER_u[71] = 0x00;
	sign->DER_u[0] = 0x30;
	sign->DER_u[1] = 0x44;
	sign->DER_u[2] = 0x02;
	sign->DER_u[3] = 0x20;
	sign->DER_u[36] = 0x02;
	sign->DER_u[37] = 0x20;
	for (size_t i = 0; i < 32; i++) {
	    sign->DER_u[4+i] = sign->r[i];
	    sign->DER_u[38+i] = sign->s[i];
	}
	DER_len = 70;
    }
    sign->DER_len = DER_len;
    err = uint8_to_char(sign->DER_u, sign->DER, DER_len);
    if (err) {
	fprintf(stderr, "Failed to convert signature s into a string format\n");
    }	

 allocerr10:
     gcry_sexp_release(s_key_pub);
 allocerr9:
    gcry_ctx_release(s_key_ctx);    
 allocerr8:
    gcry_sexp_release(s_data);
 allocerr7:
    gcry_sexp_release(s_key);
 allocerr6:
    gcry_free(data_hash);
 allocerr5:    
    gcry_free(s_sign);
 allocerr4:
    gcry_free(s_key_swap);	
 allocerr3:
    gcry_free(s_data_buff);    
 allocerr2:
    gcry_free(s_key_buff);	
 allocerr1:

#undef BUFF_SIZE
    return err;
}

gcry_error_t base58_decode(uint8_t *key, size_t key_length, char *base58, size_t char_length) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    gcry_mpi_t mpi_factor = NULL;
    gcry_mpi_t mpi_swap = NULL;
    gcry_mpi_t mpi_result = NULL;
    gcry_mpi_t mpi_sum = NULL;
    uint8_t *string_swap = NULL;
    char base58_arr[] = BASE58;

    if (key == NULL || char_length < 1) {
	fprintf (stderr, "key can't be empty\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (base58 == NULL) {
	fprintf(stderr, "base58 can´t be NULL\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	

    mpi_factor = gcry_mpi_snew(char_length*8);
    if (mpi_factor == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
    mpi_swap = gcry_mpi_snew(char_length*8);
    if (mpi_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr2;
    }
    mpi_result = gcry_mpi_snew(char_length*8);
    if (mpi_result == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr3;
    }
    mpi_sum = gcry_mpi_snew(char_length*8);
    if (mpi_sum == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr4;
    }
    string_swap = (uint8_t *)gcry_calloc_secure(char_length, sizeof(uint8_t));
    if (string_swap == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr5;
    }

    for (size_t i = 0; i < char_length; i++) {
	for (size_t j = 0; j < 58; j++) {
	    if (base58[char_length-i-1] == base58_arr[j]) {
		string_swap[i] = j;
		break;
	    }
	}
    }

    mpi_result = gcry_mpi_set_ui(mpi_result, string_swap[0]);
    for (size_t i = 1; i < char_length; i++) {
	mpi_factor = gcry_mpi_set_ui(mpi_factor, 1);
	mpi_swap = gcry_mpi_set_ui(mpi_swap, 0);
	mpi_sum = gcry_mpi_set_ui(mpi_sum, 0);
	for (size_t j = 0; j < i; j++){
	    gcry_mpi_mul_ui(mpi_swap, mpi_factor, 58);
	    mpi_factor = gcry_mpi_set(mpi_factor, mpi_swap);
	}
	gcry_mpi_mul_ui(mpi_sum, mpi_swap, string_swap[i]);
	gcry_mpi_add(mpi_result, mpi_result, mpi_sum);
    }
    
    gcry_mpi_print(GCRYMPI_FMT_USG, key, key_length, NULL, mpi_result);	   
    if (err) {
	fprintf(stderr, "Failed to convert mpi into uint8_t\n");
	goto allocerr6;
    }

 allocerr6:
    gcry_free(string_swap);
 allocerr5:
    gcry_mpi_release(mpi_sum);
 allocerr4:
    gcry_mpi_release(mpi_result);
 allocerr3:
    gcry_mpi_release(mpi_swap);
 allocerr2:
    gcry_mpi_release(mpi_factor);
 allocerr1:
    return err;
}
