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
    char path[200] = {0};
    char query[500] = {0};
    size_t query_bytes = 0;
    sqlite3_stmt *pstmt = NULL;
    const char **query_tail = {0};
    
    if (strlen(db_name) > 54) {
	fprintf(stderr, "Database file name too long.\n");
	err = -1;
	return err;
    }

    strcpy(path, "./");
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
    strcpy(query, "CREATE TABLE account ("
	   "id INTEGER PRIMARY KEY,"
	   "private_key TEXT,"
	   "chain_code TEXT"
	   ");");
    
    query_bytes = strlen(query);
 
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
    memset(query, 0, strlen(query));
    strcpy(query, "CREATE TABLE receive ("
	   "id INTEGER PRIMARY KEY,"
	   "address TEXT"
	   ");");

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
    memset(query, 0, strlen(query));
    strcpy(query, "CREATE TABLE change ("
	   "id INTEGER PRIMARY KEY,"
	   "address TEXT"
	   ");");

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

int32_t query_count(char *db_name, char *table, char *key, char * condition) {
    int32_t err = 0;
    sqlite3 *pdb = NULL;
    char path[200] = {0};
    char query[300] = {0};
    size_t query_bytes = 0;
    sqlite3_stmt *pstmt = NULL;
    const char **query_tail = {0};
    int32_t row_count = 0;
    
    if (strlen(db_name) > 54) {
	fprintf(stderr, "Database file name too long.\n");
	err = -1;
	return err;
    }
    if (db_name == NULL || table == NULL) {
	fprintf(stderr, "db_name and table can't be NULL.\n");
	err = -1;
	return err;
    }
    if (condition == NULL) {
	condition = "";
    }
    
    strcpy(path, "./");
    strcat(path, db_name);
    strcat(path, ".db");

    // Begin SELECT query
    strcpy(query, "SELECT COUNT(");
    strcat(query, key);
    strcat(query, ") FROM ");
    strcat(query, table);
    strcat(query, " ");
    strcat(query, condition);
    strcat(query, ";");
    query_bytes = strlen(query);
    // End Query

    err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READONLY, NULL);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to open database file: %s", db_name);
	return -err;
    }
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    err = sqlite3_step(pstmt);
    if (err == SQLITE_ERROR) {
	fprintf(stderr, "Not possible to execute query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }

    // Count columns/row returned from query
    err = sqlite3_data_count(pstmt);
    if (!err) {
	fprintf(stderr, "Query returned no data\n");
	return -err;
    }
    row_count = sqlite3_column_int(pstmt,0);
    
    err = sqlite3_finalize(pstmt);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to destroy statement: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    err = sqlite3_close_v2(pdb);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to close open database file: %s\n", db_name);
	return -err;
    }	
    
    return row_count;
}

int32_t read_key(query_return_t *query_return, char *db_name, char *table, char *key, char *condition) {
    int32_t err = 0;
    sqlite3 *pdb = NULL;
    char path[200] = {0};
    char query[300] = {0};
    size_t query_bytes = 0;
    sqlite3_stmt *pstmt = NULL;
    const char **query_tail = {0};
    uint32_t count = 0;
    
    if (strlen(db_name) > 54) {
	fprintf(stderr, "Database file name too long.\n");
	err = -1;
	return err;
    }
    if (db_name == NULL || table == NULL) {
	fprintf(stderr, "db_name and table can't be NULL.\n");
	err = -1;
	return err;
    }
    if (condition == NULL) {
	condition = "";
    }
    
    strcpy(path, "./");
    strcat(path, db_name);
    strcat(path, ".db");

    // Begin SELECT query
    strcpy(query, "SELECT id, ");
    strcat(query, key);
    strcat(query, " FROM ");
    strcat(query, table);
    strcat(query, " ");
    strcat(query, condition);
    strcat(query, ";");
    query_bytes = strlen(query);
    // End Query

    err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READONLY, NULL);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to open database file: %s", db_name);
	return -err;
    }        
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    err = sqlite3_step(pstmt);
    if (err == SQLITE_ERROR) {
	fprintf(stderr, "Not possible to execute query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }

    while (err == SQLITE_ROW) {
	query_return[count].id = sqlite3_column_int(pstmt, 0);
	strcpy(query_return[count].value, (char *)sqlite3_column_text(pstmt, 1));
	count++;
	err = sqlite3_step(pstmt);
	if (err == SQLITE_ERROR) {
	    fprintf(stderr, "Not possible to execute query: %s with error: %d\n", query, err);
	    return -err;
	}
    }

    err = sqlite3_finalize(pstmt);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to destroy statement: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    err = sqlite3_close_v2(pdb);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to close open database file: %s\n", db_name);
	return -err;
    }	
    
    return err;
}

int32_t insert_key(query_return_t *query_insert, uint32_t num_values, char *db_name, char *table, char *key) {
    int32_t err = 0;
    sqlite3 *pdb = NULL;
    char path[200] = {0};
    char query[300] = {0};
    size_t query_bytes = 0;
    sqlite3_stmt *pstmt = NULL;
    const char **query_tail = {0};
    char *errmsg = NULL;
    
    if (strlen(db_name) > 54) {
	fprintf(stderr, "Database file name too long.\n");
	err = -1;
	return err;
    }
    if (db_name == NULL || table == NULL) {
	fprintf(stderr, "db_name and table can't be NULL.\n");
	err = -1;
	return err;
    }
    
    strcpy(path, "./");
    strcat(path, db_name);
    strcat(path, ".db");

    err = sqlite3_open_v2(path, &pdb, SQLITE_OPEN_READWRITE, NULL);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to open database file: %s", db_name);
	return -err;
    }        

    // Begin INSERT query
    strcpy(query, "INSERT INTO ");
    strcat(query, table);
    strcat(query, " (id, ");
    strcat(query, key);
    strcat(query, ") VALUES(?, ?");
    strcat(query, ");");
    query_bytes = strlen(query);
    // End Query
    
    err = sqlite3_prepare_v2(pdb, query, query_bytes, &pstmt, query_tail);
    if(err != SQLITE_OK) {
	fprintf(stderr, "Not possible to process query: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    
    sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &errmsg);
    for (uint32_t i = 0; i < num_values; i++) {
	err = sqlite3_bind_int64(pstmt, 1, query_insert[i].id);
	if (err != SQLITE_OK) {
	    fprintf(stderr, "Problem binding index with error: %s\n", sqlite3_errmsg(pdb));
	    return -err;
	}
	err = sqlite3_bind_text(pstmt, 2, query_insert[i].value, -1, SQLITE_TRANSIENT);
	if (err != SQLITE_OK) {
	    fprintf(stderr, "Problem binding index with error: %s\n", sqlite3_errmsg(pdb));
	    return -err;
	}
	
	err = sqlite3_step(pstmt);	
	if (err != SQLITE_DONE) {
	    fprintf(stderr, "Not possible to execute query: %s with error number %d\n", query, err);
	    return -err;
	}
	sqlite3_clear_bindings(pstmt);
	sqlite3_reset(pstmt);
    }
    sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &errmsg);
    
    err = sqlite3_finalize(pstmt);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to destroy statement: %s with error: %s\n", query, sqlite3_errmsg(pdb));
	return -err;
    }
    err = sqlite3_close_v2(pdb);
    if (err != SQLITE_OK) {
	fprintf(stderr, "Not possible to close open database file: %s\n", db_name);
	return -err;
    }	
    
    return err;
}
