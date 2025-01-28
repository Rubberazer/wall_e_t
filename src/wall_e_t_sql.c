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
	fprintf(stderr, "Database file name too long.\n");
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
	fprintf(stdout, "Database file: '%s.db' already exists, do you want to overwrite it? (yes/no)\n", db_name);
	err = yes_no_menu();
	if (err == 2 || !err) {
	    fprintf(stdout, "Nothing changed\n");
	    return 0;
	}
	else {
	    fprintf(stdout, "Are you sure? (yes/no)\n");
	    err = yes_no_menu();
	    if (err == 2 || !err) {
		fprintf(stdout, "Nothing changed\n");
		return 0;
	    }  
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
	}
    }
    else {
	err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (err != SQLITE_OK) {
	    fprintf(stderr, "Not possible to create database file: %s with error: %d\n", db_name, err);
	    return err;
	}
    }

    // Create account table
    char *query = "CREATE TABLE account ("
	"id INTEGER PRIMARY KEY,"
	"private_key TEXT,"
	"private_key_address TEXT,"
	"public_key TEXT,"
	"public_key_address TEXT"
	"chain_code TEXT"
	");";
    
    size_t query_bytes = strlen(query);
    sqlite3_stmt *pstmt = NULL;
    const char **query_tail = {0};
    
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }
    err = sqlite3_step(pstmt);
    if (err != SQLITE_DONE) {
	fprintf(stderr, "Not possible to execute query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }

    // Create receive table
    query = "CREATE TABLE receive ("
	"id INTEGER PRIMARY KEY,"
	"private_key TEXT,"
	"private_key_address TEXT,"
	"public_key TEXT,"
	"address TEXT"
	");";

    err = sqlite3_reset(pstmt);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Failed to reset query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }
    err = sqlite3_step(pstmt);
    if (err != SQLITE_DONE) {
	fprintf(stderr, "Not possible to execute query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }

    // Create change table
    query = "CREATE TABLE change ("
	"id INTEGER PRIMARY KEY,"
	"private_key TEXT,"
	"private_key_address TEXT,"
	"public_key TEXT,"
	"address TEXT"
	");";

    err = sqlite3_reset(pstmt);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Failed to reset query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }
    err = sqlite3_step(pstmt);
    if (err != SQLITE_DONE) {
	fprintf(stderr, "Not possible to execute query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }

    err = sqlite3_finalize(pstmt);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to destroy statement: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return err;
    }      
    err = sqlite3_close_v2(pdb);
    fprintf(stdout, "Database created sucessfully: %s.db\n", db_name);
    
    return err;
}
    
