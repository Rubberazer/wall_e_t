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

#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio_ext.h>
#include <wall_e_t.h>

void print_usage(void) {
    fprintf(stdout, "wallet usage:\n"
	    "    -create                  Creates a new Bitcoin wallet\n"
	    "    -show key                Shows wallet Root Private key\n"
	    "    -show addresses          Shows all bitcoin addresses in wallet\n"
	    "    -show keys               Shows all bitcoin addresses and their corresponding private keys for each address in wallet\n"
	    "    -recover                 Recovers a wallet by using the list of mnemonic words and passphrase\n"
	    "    -receive                 Receive bitcoin, a new bitcoin address will be created\n"
	    "    -balance                 Balance for all addresses in wallet in satoshis\n"
	    "    -help                    Shows this\n");
}

int32_t yes_no_menu(void) {
    int32_t err = 0;
    char answer[5] = "";
    
    while (1) {
	uint32_t pos = 0;
	fgets(answer, 5, stdin);
	pos = strcspn(answer, "\n");
	answer[pos] = 0;
	if (!strcmp("yes", answer) || !strcmp("Yes", answer)) {
	    err = 1;
	    break;
	}
	if (!strcmp("no", answer) || !strcmp("No", answer)) {
	    err = 2;
	    break;
	}
	__fpurge(stdin);
	fprintf(stdout, "Answer yes or no please\n");
    }
    return err;
}

int32_t getpasswd(char *passwd, password_t pass_type) {
    int32_t err = 0;
    char pass[70] = "";
    uint32_t pass_max = 0;
    uint32_t pass_min = 0;
    struct termios term, term_old;
    
    switch (pass_type){
    case password:
	strcpy(pass, "password");
	pass_max = PASSWD_MAX-1;
	pass_min = PASSWD_MIN;
	break;
    case passphrase:
	strcpy(pass, "passphrase");
	pass_max = PASSP_MAX-1;
	pass_min = 0;
	break;
    default:
	fprintf (stderr, "pass_type should be either: password or passphrase\n");
	err = -1;
	return err;
    }
    
    tcgetattr(fileno(stdin), &term_old);
    term = term_old;
    term.c_lflag &= ~ECHO;
    err = tcsetattr(fileno(stdin), TCSANOW, &term);
    if (err) {
	fprintf(stderr, "Problem setting up terminal, exiting function\n");
	err = -1;
	return err;
    }
    uint8_t pass_marker = 0;
    while (strlen(passwd) < pass_min || strlen(passwd) > pass_max || ((pass_type == passphrase) && (pass_marker == 0))) {
	uint32_t pos = 0;
	fprintf(stdout, "Enter %s, it should be a minimum of %u and a maximum of %u characters long:\n", pass, pass_min, pass_max);
	fgets(passwd, pass_max+1, stdin);
	pos = strcspn(passwd, "\n");
	passwd[pos] = 0;
	pass_marker = 1;
	if (strlen(passwd) > pass_max) {
	    fprintf(stdout, "P%s is too long, please try again\n", &pass[1]);
	    pass_marker = 0;
	}
	else if (strlen(passwd) < pass_min) {
	    fprintf(stdout, "P%s is too short, please try again\n", &pass[1]);
	    pass_marker = 0;
	}
	__fpurge(stdin);
    }

    tcsetattr(fileno(stdin), TCSANOW, &term_old);
    if (err) {
	fprintf(stderr, "Problem setting up terminal, exiting function\n");
	err = -1;
	return err;
    }

    return err;	
}

int32_t create_wallet(void) {
    typedef char *word_t[PASSWD_MAX];
    gcry_error_t err = GPG_ERR_NO_ERROR;
    int32_t error = 0;
    mnemonic_t *mnem = NULL;
    key_pair_t *child_keys = NULL;
    uint32_t nwords = 0;
    word_t *s_salt = NULL;
    word_t *passwd = NULL;
    char nwords_answer[5] = "";
    uint8_t nwords_menu = 1;
    uint8_t pass_ctrl = 1;
    query_return_t *query_insert = NULL;

    err = libgcrypt_initializer();
    if (!err) {
	fprintf (stderr, "Not possible to initialize libgcrypt library\n");
	error = -1;
	return error;
    }
    
    fprintf(stdout, "A standard BIP84 Bitcoin wallet will be created, the keys derivation scheme is as follows.\n"
	    "Maybe is a good idea if you disconnect your computer from the Internet now. It will be safer.\n"
	    "\t\t\t*********************\n"
	    "\t\t\t*  m'/84'/0'/0'/0   *\n"
	    "\t\t\t*********************\n"
	    "A standard mnemonic phrase in english will be generated according to the BIP39 standard, this phrase will allow you to recover your wallet in case of wallet loss, e.g. wallet database file corruption or similar.\n"
	    "This mnemonic phrase will be composed of either:\n"
	    "    -12 words .\n"
	    "    -15 words .\n"
	    "    -18 words .\n"
	    "    -21 words .\n"
	    "    -24 words .\n"
	    "Please indicate the number of words for your mnemonic phrase (answer with a number from the options above):\n");

    while(nwords_menu) {
	fgets(nwords_answer, 5, stdin);
	nwords = atoi(nwords_answer);
	switch (nwords) {
	case 12: nwords_menu = 0; 
	    break;
	case 15: nwords_menu = 0;
	    break;
	case 18: nwords_menu = 0;
	    break;
	case 21: nwords_menu = 0;
	    break;
	case 24: nwords_menu = 0;
	    break;
	default:
	    fprintf (stderr, "Number of words should be either: 12, 15, 18, 21 or 24\n");
	    memset(nwords_answer, 0, strlen(nwords_answer)*sizeof(char));
	    nwords = 0;
	}
    }

    mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
    if (mnem == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    child_keys = (key_pair_t *)gcry_calloc_secure(3, sizeof(key_pair_t));
    if (child_keys == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    s_salt = (word_t *)gcry_calloc_secure(2, sizeof(word_t));
    if (s_salt == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr3;
    }
    passwd = (word_t *)gcry_calloc_secure(2, sizeof(word_t));
    if (passwd == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr4;
    }
    query_insert = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
    if (query_insert == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr5;
    }

    fprintf(stdout, "Along with your mnemonic phrase, an extra word or passphrase can be added for further security, YOU WILL HAVE TO KEEP THIS PASSPHRASE ALONG WITH YOUR MNEMONIC PHRASE IN A SAFE PLACE, AS IT WILL BE REQUIRED TO RECOVER YOUR WALLET\n");    
    while(pass_ctrl) {
	error = getpasswd((char *)(&s_salt[0]), passphrase);
	if (error) {
	    fprintf(stderr, "Problem getting passphrase from user\n");
	    error = 0;
	}
	fprintf(stdout, "Confirm your passphrase please\n");
	error = getpasswd((char *)(&s_salt[1]), passphrase);
	if (error) {
	    fprintf(stderr, "Problem getting passphrase from user\n");
	    error = 0;
	}
	if (strcmp((char *)(&s_salt[0]), (char *)(&s_salt[1]))) {
	    fprintf(stdout, "Passphrase doesn't match, please type it again\n");
	    memset(s_salt, 0, 2*sizeof(word_t));
	}
	else {pass_ctrl = 0;}
    }
    fprintf(stdout, "Passphrase registered successfully\n\n");
    pass_ctrl = 1;

    fprintf(stdout, "You will also need to create a password to encrypt (AES256-GCM-SIV) your Private Root Keys into your wallet\n");
    while(pass_ctrl) {
	error = getpasswd((char *)(&passwd[0]), password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}
	fprintf(stdout, "Confirm your password please\n");
	error = getpasswd((char *)(&passwd[1]), password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}
	if (strcmp((char *)(&passwd[0]), (char *)(&passwd[1]))) {
	    fprintf(stdout, "Password doesn't match, please type it again\n");
	    memset(passwd, 0, 2*sizeof(word_t));
	}
	else {pass_ctrl = 0;}
    }
    fprintf(stdout, "Password registered successfully\n\n\n");
    // Obtain mnemonic + root keys
    err = create_mnemonic((char *)(&s_salt[1]), nwords, mnem);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem creating mnemonic\n");
	goto allocerr6;
    }
    // Deriving keys
    // Purpose: BIP84
    err = key_deriv(&child_keys[0], mnem->keys.key_priv, mnem->keys.chain_code, BIP84, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving purpose keys\n");
	goto allocerr6;
    }	
    // Coin: Bitcoin
    err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving coin keys\n");
	goto allocerr6;
    }	
    // Account keys
    err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving account keys\n");
	goto allocerr6;
    }	

    query_insert->id = 0;
    query_insert->value_size = 1000;
    err = encrypt_AES256(query_insert->value, (uint8_t *)(&mnem->keys), sizeof(key_pair_t), (char *)(&passwd[1]));
    if (err) {
	fprintf(stderr, "Problem encrypting keys\n");
	error = -1;
	goto allocerr6;
    }

    error = create_wallet_db("wallet");
    if (error) {
	fprintf(stderr, "Problem creating database file, exiting\n");
	goto allocerr6;
    }
    error = insert_key(query_insert, 1, "wallet", "root", "keys");
    if (error < 0) {
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	goto allocerr6;
    }

    fprintf(stdout, "Remember that by now, you should also have an extra passphrase word plus the password to decrypt your Root Private Keys, if you forgot them, it is better to repeat the process again before transfering any coins into your wallet\n"
	    "Your mnemonic phrase is below, keep it safe and once you copy them, close this terminal screen, after that you can reconnect to the Internet if you were disconnected before:\n\n"
	    "\t%s\n\n", mnem->mnemonic);

 allocerr6:
    gcry_free(query_insert);
 allocerr5:
    gcry_free(password); 
 allocerr4:
    gcry_free(s_salt);
 allocerr3:
    gcry_free(child_keys);
 allocerr2:
    gcry_free(mnem);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);

    return error;    
}

int32_t recover_wallet(void) {
    typedef char *word_t[PASSWD_MAX];
    gcry_error_t err = GPG_ERR_NO_ERROR;
    int32_t error = 0;
    mnemonic_t *mnem = NULL;
    key_pair_t *child_keys = NULL;
    word_t *s_salt = NULL;
    word_t *passwd = NULL;
    uint8_t pass_ctrl = 1;
    query_return_t *query_insert = NULL;
    char *recover_mnem = NULL;
    char addr_answer[6] = "";
    uint32_t number_addresses = 0;
    uint8_t addresses_menu = 1;
    char bech32_address[64] = {0};
    
    err = libgcrypt_initializer();
    if (!err) {
	fprintf (stderr, "Not possible to initialize libgcrypt library\n");
	error = -1;
	return error;
    }
    
    fprintf(stdout, "This menu will help you to recover your wallet, you will need your mnemonic passphrase and passphrase word.\n"
	    "Maybe is a good idea if you disconnect your computer from the Internet now. It will be safer.\n"
	    "Your mnemonic phrase should be composed of either:\n"
	    "    -12 words .\n"
	    "    -15 words .\n"
	    "    -18 words .\n"
	    "    -21 words .\n"
	    "    -24 words .\n"
	    "You can copy&paste/type your mnemonic code now:\n");
    
    mnem = (mnemonic_t *)gcry_calloc_secure(1, sizeof(mnemonic_t));
    if (mnem == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    child_keys = (key_pair_t *)gcry_calloc_secure(5, sizeof(key_pair_t));
    if (child_keys == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    s_salt = (word_t *)gcry_calloc_secure(2, sizeof(word_t));
    if (s_salt == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr3;
    }
    passwd = (word_t *)gcry_calloc_secure(2, sizeof(word_t));
    if (passwd == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr4;
    }
    query_insert = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
    if (query_insert == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr5;
    }
    recover_mnem = (char *)gcry_calloc_secure(1000, sizeof(char));
    if (recover_mnem == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr6;
    }

    fgets(recover_mnem, 1000, stdin);
    uint32_t pos = strcspn(recover_mnem, "\n");
    recover_mnem[pos] = 0;
    
    fprintf(stdout, "Along with your mnemonic phrase, an additional passphrase si required, if you didnt have one, you can just leave it empty and press ENTER\n");    
    while(pass_ctrl) {
	error = getpasswd((char *)(&s_salt[0]), passphrase);
	if (error) {
	    fprintf(stderr, "Problem getting passphrase from user\n");
	    error = 0;
	}
	fprintf(stdout, "Confirm your passphrase please\n");
	error = getpasswd((char *)(&s_salt[1]), passphrase);
	if (error) {
	    fprintf(stderr, "Problem getting passphrase from user\n");
	    error = 0;
	}
	if (strcmp((char *)(&s_salt[0]), (char *)(&s_salt[1]))) {
	    fprintf(stdout, "Passphrase doesn't match, please type it again\n");
	    memset(s_salt, 0, 2*sizeof(word_t));
	}
	else {pass_ctrl = 0;}
    }
    fprintf(stdout, "Passphrase registered successfully\n\n");
    pass_ctrl = 1;

    // Obtain mnemonic + root keys
    err = recover_from_mnemonic(recover_mnem, (char *)(&s_salt[1]), mnem);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem recovering from mnemonic\n");
	goto allocerr7;
    }

    fprintf(stdout, "You will also need to create a password to encrypt (AES256-GCM-SIV) your Private Root Keys into your wallet\n");
    while(pass_ctrl) {
	error = getpasswd((char *)(&passwd[0]), password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}
	fprintf(stdout, "Confirm your password please\n");
	error = getpasswd((char *)(&passwd[1]), password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}
	if (strcmp((char *)(&passwd[0]), (char *)(&passwd[1]))) {
	    fprintf(stdout, "Password doesn't match, please type it again\n");
	    memset(passwd, 0, 2*sizeof(word_t));
	}
	else {pass_ctrl = 0;}
    }
    fprintf(stdout, "Password registered successfully\n\n\n");

    // Deriving keys
    // Purpose: BIP84
    err = key_deriv(&child_keys[0], mnem->keys.key_priv, mnem->keys.chain_code, BIP84, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving purpose keys\n");
	goto allocerr7;
    }	
    // Coin: Bitcoin
    err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving coin keys\n");
	goto allocerr7;
    }	
    // Account keys
    err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving account keys\n");
	goto allocerr7;
    }
    // Receive keys index = 0
    err = key_deriv(&child_keys[3], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 0, normal_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving receive keys\n");
	goto allocerr7;
    }
    // Change keys index = 1
    err = key_deriv(&child_keys[4], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 1, normal_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving change keys\n");
	goto allocerr7;
    }
    
    query_insert->id = 0;
    query_insert->value_size = 1000;
    err = encrypt_AES256(query_insert->value, (uint8_t *)(&mnem->keys), sizeof(key_pair_t), (char *)(&passwd[1]));
    if (err) {
	fprintf(stderr, "Problem encrypting keys\n");
	error = -1;
	goto allocerr7;
    }

    error = create_wallet_db("wallet");
    if (error) {
	fprintf(stderr, "Problem creating database file, exiting\n");
	goto allocerr7;
    }
    error = insert_key(query_insert, 1, "wallet", "root", "keys");
    if (error < 0) {
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	goto allocerr7;
    }

    fprintf(stdout, "How many bitcoin addresses would you like to recover in your receiving branch? Receiving addresses are the ones where coins are transfered to. Answer with a number between 0 to 1000:\n");

    while(addresses_menu) {
	fgets(addr_answer, 6, stdin);
	number_addresses = atoi(addr_answer);
	if (number_addresses > 0 && number_addresses < 1001) {	
	    addresses_menu = 0;
	}
	else if (number_addresses == 0){
	    addresses_menu = 0;
	}
	else {
	    fprintf(stdout, "Number should be between 0 and 500\n");
	}
    }
    
    if (number_addresses) {
	key_pair_t *address_keys = NULL;
	query_return_t *address_insert = NULL;
	address_keys = (key_pair_t *)gcry_calloc_secure(number_addresses, sizeof(key_pair_t));
	if (address_keys == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    goto allocerr7;
	}
	address_insert = (query_return_t *)calloc(number_addresses, sizeof(query_return_t));
	if (address_insert == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    gcry_free(address_keys);
	    goto allocerr7;
	}
	
	for (uint32_t i = 0; i < number_addresses; i++) {
	    err = key_deriv(&address_keys[i], (uint8_t *)(&child_keys[3].key_priv), (uint8_t *)(&child_keys[3].chain_code), i, normal_child);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem deriving receive keys\n");
		gcry_free(address_keys);
		free(address_insert);
		goto allocerr7;
	    }
	    err = bech32_encode(bech32_address, 64, (uint8_t *)(&address_keys[i].key_pub_comp), 33, bech32);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem creating bech32 address from public key\n");
		gcry_free(address_keys);
		free(address_insert);
		goto allocerr7;
	    }
	    address_insert[i].id = i;
	    address_insert[i].value_size = strlen(bech32_address)*sizeof(char);
	    memcpy(address_insert[i].value, bech32_address, strlen(bech32_address));
	    memset(bech32_address, 0, 64*sizeof(char));
	}
	gcry_free(address_keys);
	error = insert_key(address_insert, number_addresses, "wallet", "receive", "address");
	if (error < 0) {
	    error = -1;
	    fprintf(stderr, "Problem inserting into  database, exiting\n");
	    goto allocerr7;
	}
	free(address_insert);
    }
    
    fprintf(stdout, "How many bitcoin addresses would you like to recover in your change branch? Change addresses are the ones that receive change coins when you do a transfer. Answer with a number between 0 to 1000:\n");

    addresses_menu = 1;
    number_addresses = 0;
    memset(addr_answer, 0, 6*sizeof(char));
    while(addresses_menu) {
	fgets(addr_answer, 6, stdin);
	number_addresses = atoi(addr_answer);
	if (number_addresses > 0 && number_addresses < 1001) {	
	    addresses_menu = 0;
	}
	else if (number_addresses == 0){
	    addresses_menu = 0;
	}
	else {
	    fprintf(stdout, "Number should be between 0 and 1000\n");
	}
    }
    
    if (number_addresses) {
	key_pair_t *address_keys = NULL;
	query_return_t *address_insert = NULL;
	address_keys = (key_pair_t *)gcry_calloc_secure(number_addresses, sizeof(key_pair_t));
	if (address_keys == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    goto allocerr7;
	}
	address_insert = (query_return_t *)calloc(number_addresses, sizeof(query_return_t));
	if (address_insert == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    gcry_free(address_keys);
	    goto allocerr7;
	}

	for (uint32_t i = 0; i < number_addresses; i++) {
	    err = key_deriv(&address_keys[i], (uint8_t *)(&child_keys[4].key_priv), (uint8_t *)(&child_keys[4].chain_code), i, normal_child);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem deriving receive keys\n");
		gcry_free(address_keys);
		free(address_insert);
		goto allocerr7;
	    }
	    err = bech32_encode(bech32_address, 64, (uint8_t *)(&address_keys[i].key_pub_comp), 33, bech32);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem creating bech32 address from public key\n");
		gcry_free(address_keys);
		free(address_insert);
		goto allocerr7;
	    }
	    address_insert[i].id = i;
	    address_insert[i].value_size = strlen(bech32_address)*sizeof(char);
	    memcpy(address_insert[i].value, bech32_address, strlen(bech32_address));
	    memset(bech32_address, 0, 64*sizeof(char));
	}
	gcry_free(address_keys);
	error = insert_key(address_insert, number_addresses, "wallet", "change", "address");
	if (error < 0) {
	    error = -1;
	    fprintf(stderr, "Problem inserting into  database, exiting\n");
	    goto allocerr7;
	}
	free(address_insert);
    }
       
    fprintf(stdout, "All done, now you should try to check your addresses and balances. You can reconnect to the Internet if you were disconnected before\n");
    

 allocerr7:
    gcry_free(recover_mnem);
 allocerr6:
    gcry_free(query_insert);
 allocerr5:
    gcry_free(password); 
 allocerr4:
    gcry_free(s_salt);
 allocerr3:
    gcry_free(child_keys);
 allocerr2:
    gcry_free(mnem);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);

    return error;    
}

int32_t show_key(void) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    int32_t error = 0;
    uint32_t s_in_length = 0;
    key_pair_t *root_keys = NULL;
    query_return_t *query_return = NULL;
    char *passwd = NULL;
    key_address_t *keys_address = NULL;
    uint8_t pass_marker = 1;
    
    err = libgcrypt_initializer();
    if (!err) {
	fprintf (stderr, "Not possible to initialize libgcrypt library\n");
	error = -1;
	return error;
    }

    root_keys = (key_pair_t *)gcry_calloc_secure(1, sizeof(key_pair_t));
    if (root_keys == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    query_return = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
    if (query_return == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    passwd = (char *)gcry_calloc_secure(PASSWD_MAX, sizeof(char));
    if (passwd == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr3;
    }
    keys_address = (key_address_t *)gcry_calloc_secure(1, sizeof(key_address_t));
    if (keys_address == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr4;
    }
    
    error = read_key(query_return, "wallet", "root", "keys", "");
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr5;
    }
    
    // Message: key_pair_t + Authentication tag + IV length (12 bytes)
    s_in_length = sizeof(key_pair_t)+16+12;

    fprintf(stdout, "This menu will show your Root key on screen. Maybe it is a good idea if you disconnect your computer from the Internet now?:\n");
    fprintf(stdout, "Please type your password:\n");
    while(pass_marker) {
	error = getpasswd(passwd, password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}	
	err = decrypt_AES256((uint8_t *)root_keys, query_return->value, s_in_length, passwd);
	if (err > GPG_ERR_NO_ERROR && err != GPG_ERR_CHECKSUM) {
	    fprintf(stderr, "Wrong password, please try again\n");
	    memset(passwd, 0, PASSWD_MAX);
	    err = GPG_ERR_NO_ERROR;
	}
	else if (err == GPG_ERR_CHECKSUM) {
	    fprintf(stderr, "Authentication error, your keys could have been corrupted or tampered with\n");
	    err = GPG_ERR_NO_ERROR;
	}
	else {
	    pass_marker = 0;
	}
    }

    if (!pass_marker) {
	err = ext_keys_address(keys_address, root_keys, NULL, 0, 0, wBIP84);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem creating address from root keys\n");
	    goto allocerr5;
	}
	fprintf(stdout, "For your eyes only. This below is the Root Private Key in hexadecimal and extended key address format:\n\n"
		"\t\t\t\t\t\t\tRoot Private Key\n"
		"\t\t\tHexadecimal format\t\t\t\t\t\t\t\tExtended Key Address Format\n");	
	for (uint32_t i = 0; i < 32; i++) {
	    fprintf(stdout, "%02x", root_keys->key_priv[i]);
	}
	fprintf(stdout, " | %s\n", keys_address->xpriv);
    }

 allocerr5:
    gcry_free(keys_address);
 allocerr4:
    gcry_free(passwd);
 allocerr3:
    gcry_free(query_return);
 allocerr2:
    gcry_free(root_keys);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);
    
    return error;    
}

int32_t receive_coin(void) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    int32_t error = 0;
    key_pair_t *child_keys = NULL;
    char *passwd = NULL;
    query_return_t *query_insert = NULL;
    query_return_t *query_return = NULL;
    key_pair_t *root_keys = NULL;
    uint32_t count_addresses = 0;
    char bech32_address[64] = {0};
    uint8_t pass_marker = 1;
    uint32_t s_in_length = 0;
	
    err = libgcrypt_initializer();
    if (!err) {
	fprintf (stderr, "Not possible to initialize libgcrypt library\n");
	error = -1;
	return error;
    }

    child_keys = (key_pair_t *)gcry_calloc_secure(5, sizeof(key_pair_t));
    if (child_keys == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    passwd = (char *)gcry_calloc_secure(PASSWD_MAX, sizeof(char));
    if (passwd == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    query_insert = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
    if (query_insert == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr3;
    }
    query_return = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
    if (query_return == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr4;
    }
    root_keys = (key_pair_t *)gcry_calloc_secure(1, sizeof(key_pair_t));
    if (root_keys == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr5;
    }
    
    error = read_key(query_return, "wallet", "root", "keys", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr6;
    }
    
   // Message: key_pair_t + Authentication tag + IV length (12 bytes)
    s_in_length = sizeof(key_pair_t)+16+12;

    fprintf(stdout, "Please type your password:\n");
    while(pass_marker) {
	error = getpasswd(passwd, password);
	if (error) {
	    fprintf(stderr, "Problem getting password from user\n");
	    error = 0;
	}	
	err = decrypt_AES256((uint8_t *)root_keys, query_return->value, s_in_length, passwd);
	if (err > GPG_ERR_NO_ERROR && err != GPG_ERR_CHECKSUM) {
	    fprintf(stdout, "Wrong password, please try again:\n");
	    memset(passwd, 0, PASSWD_MAX);
	    err = GPG_ERR_NO_ERROR;
	}
	else if (err == GPG_ERR_CHECKSUM) {
	    fprintf(stderr, "Authentication error, your keys could have been corrupted or tampered with\n");
	    err = GPG_ERR_NO_ERROR;
	}
	else {
	    pass_marker = 0;
	}
    }
    
    // Deriving keys
    // Purpose: BIP84
    err = key_deriv(&child_keys[0], root_keys->key_priv, root_keys->chain_code, BIP84, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving purpose keys\n");
	goto allocerr6;
    }	
    // Coin: Bitcoin
    err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving coin keys\n");
	goto allocerr6;
    }	
    // Account keys
    err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving account keys\n");
	goto allocerr6;
    }
    // Receive keys index = 0
    err = key_deriv(&child_keys[3], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 0, normal_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving receive keys\n");
	goto allocerr6;
    }
        
    error = query_count("wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	return error;
    }
    count_addresses = error;

    err = key_deriv(&child_keys[4], (uint8_t *)(&child_keys[3].key_priv), (uint8_t *)(&child_keys[3].chain_code), count_addresses, normal_child);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem deriving receive keys\n");
	goto allocerr6;
    }
    err = bech32_encode(bech32_address, 64, (uint8_t *)(&child_keys[4].key_pub_comp), 33, bech32);
    if (err) {
	error = -1;
	fprintf(stderr, "Problem creating bech32 address from public key\n");
	goto allocerr6;
    }

    query_insert->id = count_addresses;
    query_insert->value_size = strlen(bech32_address)*sizeof(char);
    memcpy(query_insert->value, bech32_address, strlen(bech32_address)*sizeof(char));
    error = insert_key(query_insert, 1, "wallet", "receive", "address");
    if (error < 0) {
	error = -1;
	fprintf(stderr, "Problem inserting into  database, exiting\n");
	goto allocerr6;
    }

    fprintf(stdout, "This address has been added to your wallet:\n%s\n", bech32_address);

 allocerr6:
    gcry_free(root_keys);
 allocerr5:
    gcry_free(query_return);
 allocerr4:
    gcry_free(query_insert);
 allocerr3:
    gcry_free(password); 
 allocerr2:
    gcry_free(child_keys);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);

    return error;    
}

int32_t show_addresses(void) {
    int32_t error = 0;
    query_return_t *query_receive = NULL;
    query_return_t *query_change = NULL;
    uint32_t count_receive = 0;
    uint32_t count_change = 0;
    char bitcoin_address[64] = {0};
    
    error = query_count("wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	return error;
    }
    count_receive = error;

    query_receive = (query_return_t *)calloc(count_receive, sizeof(query_return_t));
    if (query_receive == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    
    error = read_key(query_receive, "wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr2;
    }

    error = query_count("wallet", "change", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	goto allocerr2;
    }
    count_change = error;

    query_change = (query_return_t *)calloc(count_change, sizeof(query_return_t));
    if (query_change == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    
    error = read_key(query_change, "wallet", "change", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr3;
    }

    fprintf(stdout, "\t\tReceive addresses\n");
    fprintf(stdout, "Id \t\tAddresses\n");
    for (uint32_t i = 0; i < count_receive; i++) {
	memcpy(bitcoin_address, &query_receive[i].value, 64*sizeof(char));
	fprintf(stdout,"%u | %s\n", query_receive[i].id, bitcoin_address);
	memset(bitcoin_address, 0, 64*sizeof(char));
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "\t\tChange addresses\n");
    fprintf(stdout, "Id \t\tAddresses\n");
    for (uint32_t i = 0; i < count_change; i++) {
	memcpy(bitcoin_address, &query_change[i].value, 64*sizeof(char));
	fprintf(stdout, "%u | %s\n", query_change[i].id, bitcoin_address);
	memset(bitcoin_address, 0, 64*sizeof(char));
    }
    
 allocerr3:
    free(query_change);
 allocerr2:    
    free(query_receive);
 allocerr1:
    
    return error;    
}

int32_t show_keys(void) {
    gcry_error_t err = GPG_ERR_NO_ERROR;
    int32_t error = 0;
    uint32_t count_receive = 0;
    uint32_t count_change = 0;
    char bitcoin_address[64] = {0};
    uint8_t pass_marker = 1;
    uint32_t s_in_length = 0;
    key_pair_t *child_keys = NULL;
    key_pair_t *root_keys = NULL;
    char *passwd = NULL;    
    query_return_t *query_root = NULL;

    err = libgcrypt_initializer();
    if (!err) {
	fprintf (stderr, "Not possible to initialize libgcrypt library\n");
	error = -1;
	return error;
    }

    // receive addresses
    error = query_count("wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	goto allocerr1;
    }
    count_receive = error;
    error = query_count("wallet", "change", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	goto allocerr1;
    }
    count_change = error;

    if (count_receive || count_change) {    
	child_keys = (key_pair_t *)gcry_calloc_secure(5, sizeof(key_pair_t));
	if (child_keys == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    goto allocerr1;
	}
	passwd = (char *)gcry_calloc_secure(PASSWD_MAX, sizeof(char));
	if (passwd == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    gcry_free(child_keys);
	    goto allocerr1;
	}    
	query_root = (query_return_t *)gcry_calloc_secure(1, sizeof(query_return_t));
	if (query_root == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    goto allocerr1;
	}
	root_keys = (key_pair_t *)gcry_calloc_secure(1, sizeof(key_pair_t));
	if (root_keys == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    goto allocerr1;
	}

	error = read_key(query_root, "wallet", "root", "keys", NULL);
	if (error < 0) {
	    fprintf(stderr, "Problem querying database, exiting\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}

	// Message: key_pair_t + Authentication tag + IV length (12 bytes)
	s_in_length = sizeof(key_pair_t)+16+12;

	fprintf(stdout, "We are going to show your private keys, maybe is a good idea if you disconnect from the Internet now?\n");
	fprintf(stdout, "Please type your password:\n");
	while(pass_marker) {
	    error = getpasswd(passwd, password);
	    if (error) {
		fprintf(stderr, "Problem getting password from user\n");
		error = 0;
	    }	
	    err = decrypt_AES256((uint8_t *)root_keys, query_root->value, s_in_length, passwd);
	    if (err > GPG_ERR_NO_ERROR && err != GPG_ERR_CHECKSUM) {
		fprintf(stdout, "Wrong password, please try again:\n");
		memset(passwd, 0, PASSWD_MAX);
		err = GPG_ERR_NO_ERROR;
	    }
	    else if (err == GPG_ERR_CHECKSUM) {
		fprintf(stderr, "Authentication error, your keys could have been corrupted or tampered with\n");
		err = GPG_ERR_NO_ERROR;
	    }
	    else {
		pass_marker = 0;
	    }
	}
    
	// Deriving keys
	// Purpose: BIP84
	err = key_deriv(&child_keys[0], root_keys->key_priv, root_keys->chain_code, BIP84, hardened_child);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem deriving purpose keys\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}
	// Coin: Bitcoin
	err = key_deriv(&child_keys[1], (uint8_t *)(&child_keys[0].key_priv), (uint8_t *)(&child_keys[0].chain_code), COIN_BITCOIN, hardened_child);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem deriving coin keys\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}	
	// Account keys
	err = key_deriv(&child_keys[2], (uint8_t *)(&child_keys[1].key_priv), (uint8_t *)(&child_keys[1].chain_code), ACCOUNT, hardened_child);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem deriving account keys\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}
	// Receive keys index = 0
	err = key_deriv(&child_keys[3], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 0, normal_child);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem deriving receive keys\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}
	// Change keys index = 1
	err = key_deriv(&child_keys[4], (uint8_t *)(&child_keys[2].key_priv), (uint8_t *)(&child_keys[2].chain_code), 1, normal_child);
	if (err) {
	    error = -1;
	    fprintf(stderr, "Problem deriving change keys\n");
	    gcry_free(child_keys);
	    gcry_free(passwd);
	    gcry_free(query_root);
	    gcry_free(root_keys);
	    goto allocerr1;
	}
    }
    
    fprintf(stdout, "\t\t\t\t\tReceive Keys & Addresses\n");
    fprintf(stdout, "Id \t\tWIF keys\t\t\t\t\t\tAddresses\n");
    if (count_receive) {
	query_return_t *query_receive = NULL;
	key_pair_t *address_receive = NULL;
	char *WIF_receive = NULL;
	query_receive = (query_return_t *)calloc(count_receive, sizeof(query_return_t));
	if (query_receive == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    goto allocerr2;
	}
	address_receive = (key_pair_t *)gcry_calloc_secure(count_receive, sizeof(key_pair_t));
	if (address_receive == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    free(query_receive);
	    goto allocerr2;
	}
	WIF_receive = (char *)gcry_calloc_secure(1, 53*sizeof(char));
	if (WIF_receive == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    free(query_receive);
	    gcry_free(address_receive);
	    goto allocerr2;
	}
	
	error = read_key(query_receive, "wallet", "receive", "address", NULL);
	if (error < 0) {
	    fprintf(stderr, "Problem querying database, exiting\n");
	    free(query_receive);
	    gcry_free(address_receive);
	    gcry_free(WIF_receive);
	    goto allocerr2;
	}
	
	for (uint32_t i = 0; i < count_receive; i++) {
	    err = key_deriv(&address_receive[i], (uint8_t *)(&child_keys[3].key_priv), (uint8_t *)(&child_keys[3].chain_code), i, normal_child);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem deriving receive keys\n");
		error = -1;
		free(query_receive);
		gcry_free(address_receive);
		gcry_free(WIF_receive);
		goto allocerr2;
	    }
	    err = WIF_encode(WIF_receive, 52, (uint8_t *)(&address_receive[i].key_priv), mainnet);
	    if (err) {
		fprintf(stderr, "Problem encoding private key into WIF format\n");
		free(query_receive);
		gcry_free(address_receive);
		gcry_free(WIF_receive);
		goto allocerr2;
	    }
	    memcpy(bitcoin_address, &query_receive[i].value, 64*sizeof(char));	
	    fprintf(stdout,"%u | %s | %s\n", query_receive[i].id, WIF_receive, bitcoin_address);	
	    memset(bitcoin_address, 0, 64*sizeof(char));
	    memset(WIF_receive, 0, 53*sizeof(char));
	}
	free(query_receive);
	gcry_free(address_receive);
	gcry_free(WIF_receive);
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "\t\t\t\t\tChange Keys & Addresses\n");
    fprintf(stdout, "Id \t\tWIF keys\t\t\t\t\t\tAddresses\n");    
    if (count_change) {
	query_return_t *query_change = NULL;
	key_pair_t *address_change = NULL;
	char *WIF_change = NULL; 
	query_change = (query_return_t *)calloc(count_change, sizeof(query_return_t));
	if (query_change == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    goto allocerr2;
	}
    	address_change = (key_pair_t *)gcry_calloc_secure(count_change, sizeof(key_pair_t));
	if (address_change == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    free(query_change);
	    goto allocerr2;
	}
	WIF_change = (char *)gcry_calloc_secure(1, 53*sizeof(char));
	if (WIF_change == NULL) {
	    fprintf (stderr, "Problem allocating memory\n");
	    error = -1;
	    free(query_change);
	    gcry_free(address_change);
	    goto allocerr2;
	}
	
	error = read_key(query_change, "wallet", "change", "address", NULL);
	if (error < 0) {
	    fprintf(stderr, "Problem querying database, exiting\n");
	    free(query_change);
	    gcry_free(address_change);
	    gcry_free(WIF_change);
	    goto allocerr2;
	}	
	for (uint32_t i = 0; i < count_change; i++) {
	    err = key_deriv(&address_change[i], (uint8_t *)(&child_keys[4].key_priv), (uint8_t *)(&child_keys[4].chain_code), i, normal_child);
	    if (err) {
		error = -1;
		fprintf(stderr, "Problem deriving change keys\n");
		free(query_change);
		gcry_free(address_change);
		gcry_free(WIF_change);
		goto allocerr2;
	    }
	    err = WIF_encode(WIF_change, 52, (uint8_t *)(&address_change[i].key_priv), mainnet);
	    if (err) {
		fprintf(stderr, "Problem encoding private key into WIF format\n");
		error = -1;
		free(query_change);
		gcry_free(address_change);
		gcry_free(WIF_change);
		goto allocerr2;
	    }
	    memcpy(bitcoin_address, &query_change[i].value, 64*sizeof(char));
	    fprintf(stdout, "%u | %s | %s\n", query_change[i].id, WIF_change, bitcoin_address);
	    memset(bitcoin_address, 0, 64*sizeof(char));
	    memset(WIF_change, 0, 53*sizeof(char));
	}
	free(query_change);
	gcry_free(address_change);
	gcry_free(WIF_change);
    }

 allocerr2:
    gcry_free(child_keys);
    gcry_free(passwd);
    gcry_free(query_root);
    gcry_free(root_keys);
 allocerr1:
    gcry_control(GCRYCTL_TERM_SECMEM);
    
    return error;    
}

int32_t wallet_balances(void) {
    int32_t error = 0;
    query_return_t *query_receive = NULL;
    query_return_t *query_change = NULL;
    uint32_t count_receive = 0;
    uint32_t count_change = 0;
    char bitcoin_address[64] = {0};
    ssize_t address_sats = 0;
    ssize_t receive_balance = 0;
    ssize_t change_balance = 0;
    
    error = query_count("wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	return error;
    }
    count_receive = error;

    query_receive = (query_return_t *)calloc(count_receive, sizeof(query_return_t));
    if (query_receive == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr1;
    }
    
    error = read_key(query_receive, "wallet", "receive", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr2;
    }

    error = query_count("wallet", "change", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database\n");
	goto allocerr2;
    }
    count_change = error;

    query_change = (query_return_t *)calloc(count_change, sizeof(query_return_t));
    if (query_change == NULL) {
	fprintf (stderr, "Problem allocating memory\n");
	error = -1;
	goto allocerr2;
    }
    
    error = read_key(query_change, "wallet", "change", "address", NULL);
    if (error < 0) {
	fprintf(stderr, "Problem querying database, exiting\n");
	goto allocerr3;
    }

    fprintf(stdout, "\t\t\tReceive addresses\n");
    fprintf(stdout, "\t\tAddress\t\t\t\tSatoshis\n");
    for (uint32_t i = 0; i < count_receive; i++) {
	memcpy(bitcoin_address, &query_receive[i].value, 64*sizeof(char));
	address_sats = address_balance(bitcoin_address);
	if (address_sats < 0) {
	    fprintf(stderr, "Failed to get balance for address: %s", bitcoin_address);
	    address_sats = 0;
	}
	fprintf(stdout,"%u | %s | %ld\n", query_receive[i].id, bitcoin_address, address_sats);
	memset(bitcoin_address, 0, 64*sizeof(char));
	receive_balance += address_sats; 
	address_sats = 0;
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "\t\t\tChange addresses\n");
    fprintf(stdout, "\t\tAddress\t\t\t\tSatoshis\n");
    for (uint32_t i = 0; i < count_change; i++) {
	memcpy(bitcoin_address, &query_change[i].value, 64*sizeof(char));
	if (error < 0) {
	    fprintf(stderr, "Failed to get balance for address: %s", bitcoin_address);
	    address_sats = 0;
	}
	fprintf(stdout, "%u | %s | %ld\n", query_change[i].id, bitcoin_address, address_sats);
	memset(bitcoin_address, 0, 64*sizeof(char));
	change_balance += address_sats; 
	address_sats = 0;
    }

    fprintf(stdout, "\nTOTAL RECEIVE BALANCE: %ld\n", receive_balance);
    fprintf(stdout, "TOTAL CHANGE BALANCE: %ld\n", receive_balance);
    
 allocerr3:
    free(query_change);
 allocerr2:    
    free(query_receive);
 allocerr1:
    
    return error;    
}
