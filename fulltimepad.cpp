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
 
// bitwise right rotation
inline uint32_t FullTimePad::rotr(uint32_t x, uint8_t shift)
{
	return (x >> shift) | (x << ((sizeof(x)<<3)-shift));
}

// bitwise left rotation
inline uint32_t FullTimePad::rotl(uint32_t x, uint8_t shift)
{
	return (x << shift) | (x >> ((sizeof(x)<<3)-shift));
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
static uint32_t *endian_8_to_32_arr(uint8_t *key)
{
	if constexpr(!is_big_endian()) {
	    for (uint8_t i=0;i<FullTimePad::keysize;i+=4) {
       		std::swap(key[i], key[i+3]);
       		std::swap(key[i+1], key[i+2]);
    	}
	}
		return reinterpret_cast<uint32_t*>(key);
}

// iterations for the main transformation loop
void FullTimePad::transformation(uint8_t *key) // length of k is 8
{
	// vector used for dynamic permutation, dynamically permutated key placeholder
	// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
	uint8_t p[keysize];

	// 32-bit array ints for key for arithmetic ARX manipulations
	uint32_t *k = endian_8_to_32_arr(key);

	for(uint8_t i=0;i<16;i++) {
		uint8_t index = i<<2;
		uint8_t i1mod = index % 8;
		uint8_t i2mod = (index+1) % 8;
		uint8_t i3mod = (index+2) % 8;
		uint8_t i4mod = (index+3) % 8;
		uint8_t imod8 = i % 8;
		uint8_t imod9 = (i+1) % 8;
	
		uint8_t rmod = i % 5; // 5 rotation values
		k[i1mod] = ( ( ((uint64_t)k[i1mod] + A[imod8]) % fp) + rotr(k[i1mod], r[rmod])  ) % fp;
	
		uint32_t sum = ((uint64_t)k[0] + k[1] + k[2] + k[3] + k[4] + k[5] + k[6] + k[7]) % fp;

		A[imod9] ^= sum;
	
		k[i2mod] = ( ( ((uint64_t)k[i2mod] + A[imod9]) % fp) + rotl(k[i2mod], r[rmod])  ) % fp; // uint64_t to make sure there is no unwanted overflow
		
		A[imod8] ^= ((uint64_t)k[i2mod] + rotr(k[i1mod], r[(i+1)%5])) % fp;
	
		k[i3mod] =( (uint64_t)(A[imod8] ^ k[i3mod]) + (A[imod9] ^ k[i4mod]) ) % fp;
		k[i4mod] =( (uint64_t)(A[imod8] ^ k[i4mod]) + (A[imod9] ^ k[i3mod]) ) % fp;
	
		// permutate the bytearray key
		dynamic_permutation(key, p, i);
	}


}

// if you want the destructor called to safely destroy key after use is over
// this is to make sure that the key is deleted safely and that the ownership of the init_key isn't managed somewhere else
inline void FullTimePad::terminate() noexcept
{
	terminate_k = true;
}

FullTimePad::FullTimePad(uint8_t *initial_key)
{
	init_key = initial_key;
}

// key: 256-bit (32-byte) key, should be allocated with length keysize
// key should be empty as it's only a place holder for the value in init_key
void FullTimePad::hash(uint8_t *key)
{
	// TODO: use the encryption_index here
	
	// make copy of key to transform and to preserve init_key
	memcpy(key, init_key, keysize);

	// permutate the key based on the V array

	// transformation iterations
	transformation(key);

}

// encrypt/decrypt
// key is the initial key, return heap allocated key output
// pt: plaintext data
// ct: ciphertext data
// length: length of pt, and ct
// encryption_index: each encrypted value needs it's own encryption index to keep keys unieqe and to avoid collisions
void FullTimePad::transform(uint8_t *pt, uint8_t *ct, uint32_t length, uint32_t encryption_index)
{
	uint8_t *key = new uint8_t[keysize];

	// generate unieqe key based on encryption index
	hash(key); // incorporate encryption index
	
	for(uint8_t i=0;i<length;i++) {
		ct[i] = pt[i] ^ key[i];
	}

	delete[] key;
}

// Destructor
FullTimePad::~FullTimePad()
{
	if (terminate_k) {
		memset(init_key, 0, keysize); // set to 0s for a safe memory deletion before deallocation
		delete[] init_key;
	}
}

#endif /* FULLTIMEPAD_CPP */
