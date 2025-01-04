/* Bitcoin wallet on the command line based on the libgcrypt library
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

#include <wall_e_t.h>

int main(int arg, char *arv[]) {
	static gcry_error_t err = 0;
	char *passwd = NULL;

	passwd = (char *)gcry_calloc_secure(66, sizeof(char));
	if (passwd == NULL) {
		err = -1;
		goto allocerr1;
	}
	
	getpasswd(passwd);
	
	gcry_free(passwd);
allocerr1:
	
exit(err);	
}
