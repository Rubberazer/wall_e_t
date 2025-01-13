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

int32_t getpasswd(char *passwd) {
    int32_t err = 0; 
    struct termios term, term_old;
	
    tcgetattr(fileno(stdin), &term_old);
    term = term_old;
    term.c_lflag &= ~ECHO;
    err = tcsetattr(fileno(stdin), TCSANOW, &term);
    if (err) {
	printf("Problem setting up terminal, exiting function\n");
	err = -1;
	return err;
    }
		
    while (passwd == NULL || strlen(passwd) < 10 || strlen(passwd) > 64) {
	uint32_t pos = 0;
	printf("Enter password, this password will encrypt your wallet's Private keys, it should be a maximum of 64 and a minimum of 10 characters long:\n");
	fgets(passwd, 66, stdin);
	pos = strcspn(passwd, "\n");
	passwd[pos] = 0;
	if (strlen(passwd) > 64) {
	    printf("Password is too long, please try again\n");
	}
	else if (strlen(passwd) < 10) {
	    printf("Password is too short, please try again\n");
	}
	else if (passwd == NULL) {
	    printf("Problem with password, please try again\n");
	}			
	__fpurge(stdin);
    }

    tcsetattr(fileno(stdin), TCSANOW, &term_old);
    if (err) {
	printf("Problem setting up terminal, exiting function\n");
	err = -1;
	return err;
    }
    printf("Password registered successfully\n");

    return err;	
}
