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

int32_t create_wallet_db(char *db_name) {
    int32_t err = 0;

    if (strlen(db_name) > 54) {
	fprintf(stderr, "Database file too long.\n");
	err = -1;
	return err;
    }
    sqlite3 *pdb = NULL;
    char path[200] = "./";
    strcat(path, db_name);
    strcat(path, ".db");
    
    err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READONLY, NULL);
    if (err == SQLITE_OK) {
	err = sqlite3_close_v2(pdb);
	fprintf(stdout, "Database file: %s already exists, do you want to overwrite it (yes/no)?\n", db_name);
	err = yes_no_menu();
	if (err == 2 || !err) {
	    fprintf(stdout, "Nothing changed\n");
	    return 0;
	}
	else {
	    err = sqlite3_close_v2(pdb);
	    err = remove(path);
	    if (err) {
		fprintf(stderr, "Error: Unable to delete the file.\n");
		return err;
	    }
	    err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	    if (err != SQLITE_OK) {
		fprintf(stderr, "Not possible to create database file: %s with error: %d\n", db_name, err);
		return err;
	    }
	    else fprintf(stdout, "Database file created sucessfully: %s\n", db_name);
	}
    }
    else {
	err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (err != SQLITE_OK) {
	    fprintf(stderr, "Not possible to create database file: %s with error: %d\n", db_name, err);
	    return err;
	}
	else fprintf(stdout, "Database file created sucessfully: %s\n", db_name);	    
    }

    err = sqlite3_close_v2(pdb);
    return err;
}
    
