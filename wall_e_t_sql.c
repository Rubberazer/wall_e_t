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
    sqlite3 *pdb = NULL;
    
    err = sqlite3_open_v2(db_name, &pdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to create database file: %s with error: %d\n", db_name, err);
	exit(EXIT_FAILURE);
    }
    else printf("Database file created sucessfully: %s\n", db_name);

    return err;
}
    
