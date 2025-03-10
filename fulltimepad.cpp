/*
 * Author: Taha
 * Date: Feb 6, 2025
 *
 * Full-Time-Pad Symmetric Stream Cipher
 *  Copyright (C) 2025  Taha
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 */

#ifndef FULLTIMEPAD_CPP
#define FULLTIMEPAD_CPP

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <assert.h>
#include <bit>
#include <array>

#include "fulltimepad.h"

consteval std::array<std::array<uint8_t, 32>, 16> FullTimePad::get_n_V() {
	return is_big_endian() ? n_V_big_endian : n_V_little_endian;
}

// dynamically permutate the key during iteration
// key: permutated 32-byte key
// p: dynamically re-purmutated key
// ni: index of dynamic permutation number n
// ni: iteration index
void FullTimePad::dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni)
{
	constexpr std::array<std::array<uint8_t, 32>, 16> n_V = get_n_V();

	for(uint8_t i=0;i<keysize;i++) {
		p[i] = key[n_V[ni][i]];
	}
	memcpy(key, p, keysize); // copy the repurmutated values
}

// convert uint8_t *key into uint32_t *k in big endian
uint32_t *FullTimePad::endian_8_to_32_arr(uint8_t *key)
{
	if constexpr(!is_big_endian()) {
	    for (uint8_t i=0;i<FullTimePad::keysize;i+=4) {
       		std::swap(key[i], key[i+3]);
       		std::swap(key[i+1], key[i+2]);
    	}
	}
	return reinterpret_cast<uint32_t*>(key);
}

template<FullTimePad::Version version>
void FullTimePad::transformation(uint8_t *key) // length of k is 8
{
	// vector used for dynamic permutation, dynamically permutated key placeholder
	// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
	uint8_t p[keysize];

	// 32-bit array ints for key for arithmetic ARX manipulations
	uint32_t *k = endian_8_to_32_arr(key);

	// run the wanted version
	if constexpr (version == FullTimePad::Version10) {
		for(uint8_t i=0;i<16;i++) {
			uint8_t index = i<<2;
			uint8_t i1mod = index % 8;
			uint8_t i2mod = (index+1) % 8;
			uint8_t i3mod = (index+2) % 8;
			uint8_t i4mod = (index+3) % 8;
			uint8_t imod8 = i % 8;
			uint8_t imod9 = (i+1) % 8;

			uint8_t rmod = i % 5; // 5 rotation values
								  // TODO: get rid of k[i1mod]. It's rotated then added, maybe add another value instead (or nothing). Like k[i3mod]
			k[i1mod] = ( (uint64_t)k[i1mod] + A[imod8]  + rotr(k[i1mod], r[rmod]) ) % fp;

			uint32_t sum = ((uint64_t)k[0] + k[1] + k[2] + k[3] + k[4] + k[5] + k[6] + k[7]) % fp;

			A[imod9] ^= sum;

			k[i2mod] = ( ((uint64_t)k[i2mod] + A[imod9]) + rotl(k[i2mod], r[rmod])  ) % fp; // uint64_t to make sure there is no unwanted overflow

			A[imod8] ^= ((uint64_t)k[i2mod] + rotr(k[i1mod], r[(i+1)%5])) % fp;

			k[i3mod] =( (uint64_t)(A[imod8] ^ k[i3mod]) + (A[imod9] ^ k[i4mod]) ) % fp;
			k[i4mod] =( (uint64_t)(A[imod8] ^ k[i4mod]) + (A[imod9] ^ k[i3mod]) ) % fp;

			// permutate the bytearray key
			dynamic_permutation(key, p, i);
		}
	} else if constexpr(version == FullTimePad::Version11) {
		for(uint8_t i=0;i<16;i++) {
			uint8_t index = i<<2;
			uint8_t i1mod = index % 8;
			uint8_t i2mod = (index+1) % 8;
			uint8_t i3mod = (index+2) % 8;
			uint8_t i4mod = (index+3) % 8;
			uint8_t imod8 = i % 8;
			uint8_t imod9 = (i+1) % 8;
		
			uint8_t rmod = i % 5; // 5 rotation values
			k[i1mod] = ( (uint64_t)k[i1mod] + A[imod8]  + rotr(k[i1mod], r[rmod]) ) % fp;
		
			uint32_t sum = ((uint64_t)k[0] + k[1] + k[2] + k[3] + k[4] + k[5] + k[6] + k[7]) % fp;

			A[imod9] = (A[imod9] ^ sum) % fp;
		
			k[i2mod] = ( ((uint64_t)k[i2mod] + A[imod9]) + rotl(k[i2mod], r[rmod])  ) % fp; // uint64_t to make sure there is no unwanted overflow
			
			A[imod8] = (A[imod8] ^ k[i2mod]) % fp;
		
			k[i3mod] = (A[imod8] ^ k[i3mod]) % fp;
			k[i4mod] = (A[imod8] ^ k[i4mod]) % fp;
		
			// permutate the bytearray key
			dynamic_permutation(key, p, i);
		}
	} else { // Version 2.0
		for(uint8_t i=0;i<16;i++) {
			uint8_t index = i<<2;
			uint8_t i1mod = index % 8;
			uint8_t i2mod = (index+1) % 8;
			uint8_t i3mod = (index+2) % 8;
			uint8_t i4mod = (index+3) % 8;
			uint8_t imod8 = i % 8;
			uint8_t imod9 = (i+1) % 8;

			uint8_t rmod = i % 5; // 5 rotation values
			k[i1mod] = k[i1mod] + rotr(k[i1mod], r[rmod]) + A[imod8];

			uint32_t sum = k[0] + k[1] + k[2] + k[3] + k[4] + k[5] + k[6] + k[7];

			A[imod9] = A[imod9] ^ sum;

			k[i2mod] = k[i2mod] + A[imod9] + rotl(k[i2mod], r[rmod]);

			A[imod8] = A[imod8] ^ k[i2mod];

			k[i3mod] = A[imod8] ^ k[i3mod];
			k[i4mod] = A[imod8] ^ k[i4mod];

			// permutate the bytearray key 4 times rather than 16 (faster, doesn't effect security too much)
			if(i % 4 == 0) {
				dynamic_permutation(key, p, i);
			}
		}
	}
}


// if you want the destructor called to safely destroy key after use is over
// this is to make sure that the key is deleted safely and that the ownership of the init_key isn't managed somewhere else
void FullTimePad::terminate() noexcept
{
	terminate_k = true;
}

FullTimePad::FullTimePad(uint8_t *initial_key)
{
	init_key = initial_key;
	transformed_key = new uint8_t[keysize];
	
}

// key: 256-bit (32-byte) key, should be allocated with length keysize
// key should be empty as it's only a place holder for the value in init_key
template<FullTimePad::Version version>
void FullTimePad::hash(uint8_t *key, uint64_t encryption_index)
{
	// Incorporate the the encryption_index here
	A[0] = encryption_index >> 32;
	A[1] = encryption_index; // implicit & 0xffffffff
	
	// reset A
	A[2] = 0x119f904f;
	A[3] = 0x73d44db5;
	A[4] = 0x3918fa83;
	A[5] = 0x5546b403;
	A[6] = 0x216c46df;
	A[7] = 0x64997dfd;
	
	// make copy of key to transform and to preserve init_key
	memcpy(key, init_key, keysize);

	// permutate the key based on the V array

	// transformation iterations
	transformation<version>(key);
}

// encrypt/decrypt
// key is the initial key, return heap allocated key output
// pt: plaintext data
// ct: ciphertext data
// length: length of pt, and ct
// encryption_index: encryption index
// version: version of encryption algorithm (1.0, 1.1, 2.0)
template<FullTimePad::Version version>
void FullTimePad::transform(uint8_t *pt, uint8_t *ct, uint32_t length, uint64_t encryption_index)
{
	// generate unieqe key based on encryption index and encrypt
	// for each 32-byte segment of the plaintext
	const uint32_t segment = length/32;
	for(uint32_t i=0;i<segment;i++) {
		hash<version>(transformed_key, encryption_index); // incorporate encryption index
		for(uint8_t j=0;j<32;j++) {
			ct[j] = pt[j] ^ transformed_key[j];
		}
		encryption_index++;
	}

	// for the remainder:
	const uint32_t final_length = length%32;
	if (final_length != 0) {
		hash<version>(transformed_key, encryption_index); // incorporate encryption index
		for(uint8_t j=0;j<final_length;j++) {
			ct[j] = pt[j] ^ transformed_key[j];
		}
	}
}

// Destructor
FullTimePad::~FullTimePad()
{
	if (terminate_k) {
		memset(init_key, 0, keysize); // set to 0s for a safe memory deletion before deallocation
		delete[] init_key;
	}

	memset(transformed_key, 0, keysize); // set to 0s for a safe memory deletion before deallocation
	delete[] transformed_key;
}

// Explicit instantiation
// For encrypt/decrypt (transform)
template void FullTimePad::transform<FullTimePad::Version10>(uint8_t *, uint8_t *, uint32_t, uint64_t);
template void FullTimePad::transform<FullTimePad::Version11>(uint8_t *, uint8_t *, uint32_t, uint64_t);
template void FullTimePad::transform<FullTimePad::Version20>(uint8_t *, uint8_t *, uint32_t, uint64_t);

// For hash
template void FullTimePad::hash<FullTimePad::Version10>(uint8_t *, uint64_t);
template void FullTimePad::hash<FullTimePad::Version11>(uint8_t *, uint64_t);
template void FullTimePad::hash<FullTimePad::Version20>(uint8_t *, uint64_t);

#endif /* FULLTIMEPAD_CPP */
