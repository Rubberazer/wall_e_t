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
 *
 * Code on this file is an adaption of the original one from the BIP173 Reference Implementations
 * at: https://github.com/sipa/bech32/tree/master/ref/c%2B%2B
 * And with its own license:
 *
 * Copyright (c) 2017, 2021 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wall_e_t.h>

uint32_t polymod(uint8_t *intermediate_address, size_t uint8_length) {
    // The input is interpreted as a list of coefficients of a polynomial over F = GF(32), with an
    // implicit 1 in front. If the input is [v0,v1,v2,v3,v4], that polynomial is v(x) =
    // 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4. The implicit 1 guarantees that
    // [v0,v1,v2,...] has a distinct checksum from [0,v0,v1,v2,...].

    // The output is a 30-bit integer whose 5-bit groups are the coefficients of the remainder of
    // v(x) mod g(x), where g(x) is the Bech32 generator,
    // x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}. g(x) is chosen in such a way
    // that the resulting code is a BCH code, guaranteeing detection of up to 3 errors within a
    // window of 1023 characters. Among the various possible BCH codes, one was selected to in
    // fact guarantee detection of up to 4 errors within a window of 89 characters.

    // Note that the coefficients are elements of GF(32), here represented as decimal numbers
    // between {}. In this finite field, addition is just XOR of the corresponding numbers. For
    // example, {27} + {13} = {27 ^ 13} = {22}. Multiplication is more complicated, and requires
    // treating the bits of values themselves as coefficients of a polynomial over a smaller field,
    // GF(2), and multiplying those polynomials mod a^5 + a^3 + 1. For example, {5} * {26} =
    // (a^2 + 1) * (a^4 + a^3 + a) = (a^4 + a^3 + a) * a^2 + (a^4 + a^3 + a) = a^6 + a^5 + a^4 + a
    // = a^3 + 1 (mod a^5 + a^3 + 1) = {9}.

    // During the course of the loop below, `c` contains the bitpacked coefficients of the
    // polynomial constructed from just the values of v that were processed so far, mod g(x). In
    // the above example, `c` initially corresponds to 1 mod g(x), and after processing 2 inputs of
    // v, it corresponds to x^2 + v0*x + v1 mod g(x). As 1 mod g(x) = 1, that is the starting value
    // for `c`.
    uint32_t c = 1;
    for (size_t i = 0; i < uint8_length; i++) {
        // We want to update `c` to correspond to a polynomial with one extra term. If the initial
        // value of `c` consists of the coefficients of c(x) = f(x) mod g(x), we modify it to
        // correspond to c'(x) = (f(x) * x + v_i) mod g(x), where v_i is the next input to
        // process. Simplifying:
        // c'(x) = (f(x) * x + v_i) mod g(x)
        //         ((f(x) mod g(x)) * x + v_i) mod g(x)
        //         (c(x) * x + v_i) mod g(x)
        // If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to compute
        // c'(x) = (c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5) * x + v_i mod g(x)
        //       = c0*x^6 + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i mod g(x)
        //       = c0*(x^6 mod g(x)) + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i
        // If we call (x^6 mod g(x)) = k(x), this can be written as
        // c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i) + c0*k(x)

        // First, determine the value of c0:
        uint8_t c0 = c >> 25;
        // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i:
        c = ((c & 0x1ffffff) << 5) ^ intermediate_address[i];

        // Finally, for each set bit n in c0, conditionally add {2^n}k(x):
        if (c0 & 1)  c ^= 0x3b6a57b2; //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
        if (c0 & 2)  c ^= 0x26508e6d; //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 +  {3}x^2 + {19}x + {13}
        if (c0 & 4)  c ^= 0x1ea119fa; //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 +  {6}x^2 + {15}x + {26}
        if (c0 & 8)  c ^= 0x3d4233dd; //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 + {12}x^2 + {30}x + {29}
        if (c0 & 16) c ^= 0x2a1462b3; // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 + {24}x^2 + {21}x + {19}
    }
    return c;
}

void expand_hrp(const char *hrp, uint8_t *hrp_uint8) {
    for (size_t i = 0; i < strlen(hrp); ++i) {
        uint8_t c = hrp[i];
	hrp_uint8[i] = c >> 5;
	hrp_uint8[i+strlen(hrp)+1] = c & 0x1f;
    }
    hrp_uint8[strlen(hrp)] = 0;
}

gcry_error_t create_checksum(const char *hrp, uint8_t *intermediate_address, size_t interm_length, encoding bech_type, uint8_t *checksum) {
    static gcry_error_t err = GPG_ERR_NO_ERROR;
    uint8_t *swap_address = NULL;

    if (strcmp(hrp, "bc")) {
	fprintf(stderr, "const char *hrp only accepted value is: \"bc\"\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }
    if (bech_type != bech32) {
	fprintf(stderr, "encoding *bech_type only accepted value is: bech32\n");
	err = gcry_error_from_errno(EINVAL);
	return err;
    }	
	
    swap_address = (uint8_t *)gcry_calloc_secure(interm_length+(strlen(hrp)*2+1), sizeof(uint8_t));
    if (swap_address == NULL) {
	err = gcry_error_from_errno(ENOMEM);
	goto allocerr1;
    }
	
    expand_hrp(hrp, swap_address);
    memcpy(swap_address+(strlen(hrp)*2+1), intermediate_address, interm_length);
    uint32_t mod = polymod(swap_address, interm_length+(strlen(hrp)*2+1)) ^ bech_type;
    for (size_t i = 0; i < 6; ++i) {        
	checksum[i] = (mod >> (5 * (5 - i))) & 31;
    }
    
    gcry_free(swap_address);
 allocerr1:
    return err;
}

/* Verify a checksum. */
encoding verify_checksum(const char *hrp, char *bech_address) { 
    encoding verif = invalid;
    uint8_t *swap_address = NULL;
    uint8_t *swap_hrp = NULL;
    uint8_t *interm_address = NULL;
    
    swap_address = (uint8_t *)gcry_calloc_secure((strlen(hrp)*2+1)+strlen(bech_address)-(strlen(hrp)+1), sizeof(uint8_t));
    if (swap_address == NULL) {
	fprintf(stderr, "Problem allocating memory for swap uint8 array\n");
	goto allocerr1;
    }
    swap_hrp = (uint8_t *)gcry_calloc_secure((strlen(hrp)*2+1), sizeof(uint8_t));
    if (swap_hrp == NULL) {
	fprintf(stderr, "Problem allocating memory for hrp uint8 array\n");
	goto allocerr2;
    } 
    interm_address = (uint8_t *)gcry_calloc_secure(strlen(bech_address)-(strlen(hrp)+1), sizeof(uint8_t));
    if (interm_address == NULL) {
	fprintf(stderr, "Problem allocating memory for swap uint8 array\n");
	goto allocerr3;
    }

    // PolyMod computes what value to xor into the final values to make the checksum 0. However, */
    // if we required that the checksum was 0, it would be the case that appending a 0 to a valid */
    // list of values would result in a new valid list. For that reason, Bech32 requires the */
    // resulting checksum to be 1 instead. In Bech32m, this constant was amended. */    

    for (size_t i = 3, j = 0; i < strlen(bech_address); i++, j++) {
	char bech_string[] = BECH32;
	char *position = strchr(bech_string, bech_address[i]);
	interm_address[j] = (uint8_t)(position-bech_string);;
    }
            
    expand_hrp(hrp, swap_hrp);
    memcpy(swap_address, swap_hrp, strlen(hrp)*2+1);    
    memcpy(swap_address+strlen(hrp)*2+1, interm_address, strlen(bech_address)-(strlen(hrp)+1));    
    uint32_t check = polymod(swap_address, (strlen(hrp)*2+1)+strlen(bech_address)-(strlen(hrp)+1));
       
    if (check == 1) {
	verif = bech32;
    }
    else if (check == 0x2bc830a3) {
	verif = bech32m;
    }
    else {
	verif = invalid;
    }
			     
    gcry_free(interm_address);
 allocerr3:
    gcry_free(swap_hrp);
 allocerr2:
    gcry_free(swap_address);
 allocerr1:
    return verif; 
} 
