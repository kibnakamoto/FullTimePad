/*
 * @Author: Taha
 * Date: Feb 6, 2025
 *
 * Full-Time-Pad Symmetric Stream Cipher
 *  Copyright (C) 2025  Taha
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 */

#ifndef REVERSE_CPP
#define REVERSE_CPP

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <random>
#include <bit>
#include <array>

#include "../fulltimepad.h"

// how the collision calculation should be performed
enum CollisionCalculation {
	incrementing_key,
	random_key
};

// inverse the key transformation
void inv_transformation(uint8_t *transformed_k)
{
	// vector used for dynamic permutation, dynamically permutated key placeholder
	// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
	uint8_t p[FullTimePad::keysize];

	// 32-bit array ints for key for arithmetic ARX manipulations
	uint32_t *k = FullTimePad::endian_8_to_32_arr(transformed_k); // length of k is 8

	uint32_t A[8] = {
		0,	// encryption index
		0,	// encryption index
		0x119f904f,
		0x73d44db5,
		0x3918fa83,
		0x5546b403,
		0x216c46df,
		0x64997dfd,
	};


	for(int8_t i=15;i>=0;i--) {
		uint8_t index = i<<2;
		uint8_t i1mod = index % 8;
		uint8_t i2mod = (index+1) % 8;
		uint8_t i3mod = (index+2) % 8;
		uint8_t i4mod = (index+3) % 8;
		uint8_t imod8 = i % 8;
		uint8_t imod9 = (i+1) % 8;
		uint8_t rmod = i % 5; // 5 rotation values

		// permutate the bytearray key
		FullTimePad::dynamic_permutation(transformed_k, p, i);

		k[i4mod] =( (uint64_t)(A[imod8] ^ k[i4mod]) - (A[imod9] ^ k[i3mod]) ) % FullTimePad::fp;

		k[i3mod] =( (uint64_t)(A[imod8] ^ k[i3mod]) - (A[imod9] ^ k[i4mod]) ) % FullTimePad::fp;
		
		A[imod8] ^= ((uint64_t)k[i2mod] + FullTimePad::rotl(k[i1mod], FullTimePad::r[(i+1)%5])) % FullTimePad::fp;

		k[i2mod] = ( ( ((uint64_t)k[i2mod] - A[imod9]) % FullTimePad::fp) - FullTimePad::rotr(k[i2mod], FullTimePad::r[rmod])  ) % FullTimePad::fp; // uint64_t to make sure there is no unwanted overflow

		// A[i2mod] ^= k[i1mod]; // add all values. interlink all values of k to A
		A[imod9] ^= ((uint64_t)k[0] - k[1] - k[2] - k[3] - k[4] - k[5] - k[6] - k[7]) % FullTimePad::fp;

		k[i1mod] = ( ( ((uint64_t)k[i1mod] - A[imod8]) % FullTimePad::fp) - FullTimePad::rotl(k[i1mod], FullTimePad::r[rmod])  ) % FullTimePad::fp;
	}
	
}

// generate a random 32-byte key
void gen_rand_key(uint8_t *key)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint8_t> dist(0, 0xff);
	for(uint8_t i=0;i<32;i++) key[i] = dist(gen);
}

int main()
{
	// if two plaintexts are the same (or are known), and the ciphertexts are known or if one plaintext and ciphertext are known. then you can find the hash(key)
	// Are there any patterns between hash(key1) xor hash(key2) where key1 and key2 have 1-bit difference?
	// And most importantly, is it possible to find the key using hash(key). Make inv_hash to test it
	// uint8_t key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0};
	uint32_t A[8] = {
		0,	// encryption index
		0,	// encryption index
		0x119f904f,
		0x73d44db5,
		0x3918fa83,
		0x5546b403,
		0x216c46df,
		0x64997dfd,
	};

	// check if when A is given as key, does it cancel out
	for(int i=0;i<8;i++) {
		key[i*4+0] = ( A[i] >> 24 ) & 0xff;
		key[i*4+1] = ( A[i] >> 16 ) & 0xff;
		key[i*4+2] = ( A[i] >> 8 ) & 0xff;
		key[i*4+3] = ( A[i] >> 0 ) & 0xff;
	}

	FullTimePad fulltimepad = FullTimePad(key);

	// print the given key	
	for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << key[i]+0;
	std::cout << std::endl;

	fulltimepad.hash(key, 0);

	// inverse the key:
	inv_transformation(key);

	for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << key[i]+0;
	std::cout << std::endl;
	return 0;
}
#pragma GCC diagnostic pop

#endif /* REVERSE_CPP */

