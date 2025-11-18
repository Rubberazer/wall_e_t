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

int main() {
    ssize_t error = 0;
    error = address_balance("bc1q40thsjx4k84gdmx2aynwqygmxwxpnsrjzzs4jv");
    if (error < 0) {
		fprintf(stderr, "Problem getting balance for address\n");
		exit(error);
    }
    printf("Satoshis: %ld\n", error);


    error = address_utxo_n("bc1q40thsjx4k84gdmx2aynwqygmxwxpnsrjzzs4jv"); 
    if (error < 0) {
		fprintf(stderr, "Problem getting number of utxos for address\n");
		exit(error);
    }

    uint32_t count_utxos = error;
    error = 0;
    utxo_t unspent[count_utxos];
    
    error = address_utxo(unspent, count_utxos, "bc1q40thsjx4k84gdmx2aynwqygmxwxpnsrjzzs4jv");
    if (error < 0) {
		fprintf(stderr, "Problem getting utxos for address\n");
		exit(error);
    }
    
    for (uint32_t i = 0; i < count_utxos; i++) { 
		for (uint32_t j = 0; j < 32; j++) {
			printf("%02x", unspent[i].txid[j]);
		}
		printf("\tVout: %u\n", unspent[i].vout); 
    }
    error = 0;
    
    exit(error);    
}
