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
inline uint32_t FullTimePad::lotr(uint32_t x, uint8_t shift)
{
	return (x << shift) | (x >> ((sizeof(x)<<3)-shift));
}

// initial static permutation of the key
// key: initial key before any permutations
void FullTimePad::static_permutation(uint8_t *key)
{
	uint8_t temp;
	
	for(int i=0;i<keysize>>1;i++) {
		temp = key[i];
		key[i] = key[V[i]];
		key[V[i]] = temp;
	}
}

// dynamically permutate the key during iteration
// key: permutated 32-byte key
// p: dynamically re-purmutated key
// ni: index of dynamic permutation number n
// ni: iteration index
void FullTimePad::dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni)
{
	constexpr std::array<std::array<uint8_t, 32>, 16> n_V = get_n_V();

	for(uint32_t i=0;i<keysize;i++) {
		p[i] = key[n_V[ni][i]];
	}
	memcpy(key, p, keysize); // copy the repurmutated values
}

// iterations for the main transformation loop
void FullTimePad::transformation(uint8_t *key) // length of k is 8
{
	// vector used for dynamic permutation, dynamically permutated key placeholder
	// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
	uint8_t p[keysize];

	// 32-bit array ints for key for arithmetic ARX manipulations
	uint32_t *k = reinterpret_cast<uint32_t*>(key);
	for(uint8_t i=0;i<16;i++) {
		uint16_t index = i<<2;
		uint8_t i1mod = index % 8;
		uint8_t i2mod = (index+1) % 8;
		uint8_t i3mod = (index+2) % 8;
		uint8_t i4mod = (index+3) % 8;
		uint8_t rmod = i % 5; // 5 rotation values
		k[i1mod] = ( ( ((uint64_t)k[i1mod] + A[i1mod]) % fp) + rotr(k[i1mod], r[rmod])  ) % fp;

		A[i2mod] ^= k[i1mod];

		k[i2mod] = ( ( ((uint64_t)k[i2mod] + A[i2mod]) % fp) + lotr(k[i2mod], r[rmod])  ) % fp; // TODO: uint64_t conversion after testing is over, this is to make sure there is no unwanted overflow
		A[i1mod] ^= ((uint64_t)k[i2mod] + rotr(k[i1mod], r[(i+1)%5])) % fp;

		k[i3mod] =( (uint64_t)(A[i1mod] ^ k[i3mod]) + (A[i2mod] ^ k[i3mod]) ) % fp;
		k[i4mod] =( (uint64_t)(A[i1mod] ^ k[i4mod])  + (A[i2mod] ^ k[i4mod]) ) % fp;

		// permutate the bytearray key
		dynamic_permutation(key, p, i%16);
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
void FullTimePad::hash(uint8_t *key)
{
	// make copy of key to transform and to preserve init_key
	memcpy(key, init_key, keysize);

	// permutate the key based on the V array
	//static_permutation(key);

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
