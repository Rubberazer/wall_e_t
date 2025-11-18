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

struct memory {
    char *response;
    size_t size;
};

static size_t cb(char *data, size_t size, size_t nmemb, void *clientp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)clientp;
 
    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if(!ptr)
		return 0;  /* out of memory */
 
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
 
    return realsize;
}

ssize_t address_balance(char * bitcoin_address) {
    ssize_t error = 0;
    char url_api[500] = "https://blockchain.info/balance?active=";
    CURL *curl;
    CURLcode res;
    struct memory chunk = {0};
    
    strcat(url_api, bitcoin_address);    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(!curl) {
		fprintf(stderr, "Request for balance via web failed\n");
		error = -1;
		return error;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url_api);

    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    //curl_easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
		fprintf(stderr, "Request for balance via web failed\n");
		error = -1;
		return error;
    }

    char swap_string[chunk.size];
    char *pos = NULL;
    uint32_t position = 0;
    const char *token = "\"final_balance\":";
    
    pos = strstr(chunk.response, token);
    pos += strlen(token);
    strcpy(swap_string, pos);
    position = strcspn(swap_string, ",");
    memset(chunk.response, 0, chunk.size);
    strncpy(chunk.response, swap_string, position);    
    error = atoi(chunk.response);
    
    free(chunk.response);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return error;
}

ssize_t address_utxo_n(char * bitcoin_address) {
    ssize_t error = 0;
    char url_api[500] = "https://blockchain.info/unspent?active=";
    CURL *curl;
    CURLcode res;
    struct memory chunk = {0};
    
    strcat(url_api, bitcoin_address);    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(!curl) {
		fprintf(stderr, "Request for unspent output via web failed\n");
		error = -1;
		return error;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url_api);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
		fprintf(stderr, "Request for unspent via web failed\n");
		error = -1;
		return error;
    }

    char *pos = NULL;
    uint32_t count = 0;
    char *token = "\"tx_hash_big_endian\":\"";

    pos = chunk.response;
    while ((pos = strstr(pos, token))) {
		count++;
		pos++;
    }
    error = count;
    
    free(chunk.response);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return error;
}

ssize_t address_utxo(utxo_t *unspent, size_t unspent_length, char * bitcoin_address) {
    ssize_t error = 0;
    char url_api[500] = "https://blockchain.info/unspent?active=";
    CURL *curl;
    CURLcode res;
    struct memory chunk = {0};
    
    strcat(url_api, bitcoin_address);    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(!curl) {
		fprintf(stderr, "Request for unspent output via web failed\n");
		error = -1;
		return error;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url_api);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
		fprintf(stderr, "Request for unspent via web failed\n");
		error = -1;
		return error;
    }

    char swap_string[chunk.size];
    char *pos = NULL;
    uint32_t count = 0;
    uint32_t position = 0;
    char *token = "\"tx_hash_big_endian\":\"";

    pos = chunk.response;
    while ((pos = strstr(pos, token))) {
		count++;
		pos++;
    }
    if (count > unspent_length) {
		fprintf(stderr, "Size of array reserved for unspent too small\n");
		error = -1;
		return error;
    }
    
    pos  = NULL;
    strcpy(swap_string, chunk.response);
    pos = swap_string;
    for (size_t i = 0; i < count; i++) {
		pos = strstr(pos, token);
		pos += strlen(token);
		strcpy(swap_string, pos);
		position = strcspn(swap_string, "\"");
		char_to_uint8(swap_string, (uint8_t *)&unspent[i].txid, position);
    }

    token = "\"tx_output_n\":";
    pos  = NULL;
    char swap_number[100] = "";
    strcpy(swap_string, chunk.response);
    pos = swap_string;
    for (size_t i = 0; i < count; i++) {
		pos = strstr(pos, token);
		pos += strlen(token);
		strcpy(swap_string, pos);
		position = strcspn(swap_string, ",");
		strncpy(swap_number, swap_string, position);
		unspent[i].vout = atoi(swap_number);
		memset(swap_number, 0, 100*sizeof(char));
    }
    error = count;
    
    free(chunk.response);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return error;
}
