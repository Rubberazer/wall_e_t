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

#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio_ext.h>
#include <wall_e_t.h>

int32_t yes_no_menu(void) {
    int32_t err = 0;
    char answer[5] = "";
    
    while (strcmp("yes", answer) || strcmp("no", answer) || strcmp("Yes", answer) || strcmp("No", answer)) {
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
    struct termios term, term_old;
    
    switch (pass_type){
    case password:
	strcpy(pass, "password");
	break;
    case passphrase:
	strcpy(pass, "passphrase");
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
		
    while (passwd == NULL || strlen(passwd) < 10 || strlen(passwd) > 64) {
	uint32_t pos = 0;
	fprintf(stdout, "Enter %s, this %s will encrypt your wallet's Private keys, it should be a maximum of 64 and a minimum of 10 characters long:\n", pass, pass);
	fgets(passwd, 66, stdin);
	pos = strcspn(passwd, "\n");
	passwd[pos] = 0;
	if (strlen(passwd) > 64) {
	    fprintf(stdout, "P%s is too long, please try again\n", &pass[1]);
	}
	else if (strlen(passwd) < 10) {
	    fprintf(stdout, "P%s is too short, please try again\n", &pass[1]);
	}
	else if (passwd == NULL) {
	    fprintf(stdout, "Problem with %s, please try again\n", pass);
	}			
	__fpurge(stdin);
    }

    tcsetattr(fileno(stdin), TCSANOW, &term_old);
    if (err) {
	fprintf(stderr, "Problem setting up terminal, exiting function\n");
	err = -1;
	return err;
    }
    fprintf(stdout, "P%s registered successfully\n", &pass[1]);

    return err;	
}
