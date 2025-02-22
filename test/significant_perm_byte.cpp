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

#ifndef BEST_PERMUTATION_CPP
#define BEST_PERMUTATION_CPP

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <random>
#include <bit>
#include <array>

// print best permutation matrix after signal interrupt
static bool doprint = false;

// how the collision calculation should be performed
enum CollisionCalculation {
	incrementing_key,
	random_key
};

// check endiannes before assigning n_V to big/little endian version
static consteval bool is_big_endian() {
	return std::endian::native == std::endian::big;
}


// 256-bit Full-Time-Pad Cipher
class FullTimePad
{
	public:

			// ideal permutations: would have 1 byte shifted to each another 32-bit number.
			// e.g. byte 0 goes to byte 4
			static constexpr std::array<std::array<uint8_t, 32>, 16> n_V_big_endian = {{
				{0, 4, 8, 12, 16, 20, 24, 28, 1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31},
				{4, 8, 12, 0, 20, 24, 28, 16, 5, 9, 13, 1, 21, 25, 29, 17, 6, 10, 14, 2, 22, 26, 30, 18, 7, 11, 15, 3, 23, 27, 31, 19}, 
				{8, 12, 0, 4, 24, 28, 16, 20, 9, 13, 1, 5, 25, 29, 17, 21, 10, 14, 2, 6, 26, 30, 18, 22, 11, 15, 3, 7, 27, 31, 19, 23},
				{12, 0, 4, 8, 28, 16, 20, 24, 13, 1, 5, 9, 29, 17, 21, 25, 14, 2, 6, 10, 30, 18, 22, 26, 15, 3, 7, 11, 31, 19, 23, 27},
				{12, 28, 13, 29, 14, 30, 15, 31, 0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23, 8, 24, 9, 25, 10, 26, 11, 27},
				{28, 13, 29, 12, 30, 15, 31, 14, 16, 1, 17, 0, 18, 3, 19, 2, 20, 5, 21, 4, 22, 7, 23, 6, 24, 9, 25, 8, 26, 11, 27, 10},
				{13, 29, 12, 28, 15, 31, 14, 30, 1, 17, 0, 16, 3, 19, 2, 18, 5, 21, 4, 20, 7, 23, 6, 22, 9, 25, 8, 24, 11, 27, 10, 26},
				{29, 12, 28, 13, 31, 14, 30, 15, 17, 0, 16, 1, 19, 2, 18, 3, 21, 4, 20, 5, 23, 6, 22, 7, 25, 8, 24, 9, 27, 10, 26, 11},
				{29, 31, 17, 19, 21, 23, 25, 27, 12, 14, 0, 2, 4, 6, 8, 10, 28, 30, 16, 18, 20, 22, 24, 26, 13, 15, 1, 3, 5, 7, 9, 11},
				{31, 17, 19, 29, 23, 25, 27, 21, 14, 0, 2, 12, 6, 8, 10, 4, 30, 16, 18, 28, 22, 24, 26, 20, 15, 1, 3, 13, 7, 9, 11, 5},
				{17, 19, 29, 31, 25, 27, 21, 23, 0, 2, 12, 14, 8, 10, 4, 6, 16, 18, 28, 30, 24, 26, 20, 22, 1, 3, 13, 15, 9, 11, 5, 7},
				{19, 29, 31, 17, 27, 21, 23, 25, 2, 12, 14, 0, 10, 4, 6, 8, 18, 28, 30, 16, 26, 20, 22, 24, 3, 13, 15, 1, 11, 5, 7, 9},
				{19, 27, 2, 10, 18, 26, 3, 11, 29, 21, 12, 4, 28, 20, 13, 5, 31, 23, 14, 6, 30, 22, 15, 7, 17, 25, 0, 8, 16, 24, 1, 9},
				{27, 2, 10, 19, 26, 3, 11, 18, 21, 12, 4, 29, 20, 13, 5, 28, 23, 14, 6, 31, 22, 15, 7, 30, 25, 0, 8, 17, 24, 1, 9, 16},
				{2, 10, 19, 27, 3, 11, 18, 26, 12, 4, 29, 21, 13, 5, 28, 20, 14, 6, 31, 23, 15, 7, 30, 22, 0, 8, 17, 25, 1, 9, 16, 24},
				{10, 19, 27, 2, 11, 18, 26, 3, 4, 29, 21, 12, 5, 28, 20, 13, 6, 31, 23, 14, 7, 30, 22, 15, 8, 17, 25, 0, 9, 16, 24, 1}
			}};
			
			// LITTLE ENDIAN:
			static constexpr std::array<std::array<uint8_t, 32>, 16> n_V_little_endian = {{
				{12, 8, 4, 0, 28, 24, 20, 16, 13, 9, 5, 1, 29, 25, 21, 17, 14, 10, 6, 2, 30, 26, 22, 18, 15, 11, 7, 3, 31, 27, 23, 19},
				{0, 12, 8, 4, 16, 28, 24, 20, 1, 13, 9, 5, 17, 29, 25, 21, 2, 14, 10, 6, 18, 30, 26, 22, 3, 15, 11, 7, 19, 31, 27, 23},
				{4, 0, 12, 8, 20, 16, 28, 24, 5, 1, 13, 9, 21, 17, 29, 25, 6, 2, 14, 10, 22, 18, 30, 26, 7, 3, 15, 11, 23, 19, 31, 27},
				{8, 4, 0, 12, 24, 20, 16, 28, 9, 5, 1, 13, 25, 21, 17, 29, 10, 6, 2, 14, 26, 22, 18, 30, 11, 7, 3, 15, 27, 23, 19, 31},
				{29, 13, 28, 12, 31, 15, 30, 14, 17, 1, 16, 0, 19, 3, 18, 2, 21, 5, 20, 4, 23, 7, 22, 6, 25, 9, 24, 8, 27, 11, 26, 10},
				{12, 29, 13, 28, 14, 31, 15, 30, 0, 17, 1, 16, 2, 19, 3, 18, 4, 21, 5, 20, 6, 23, 7, 22, 8, 25, 9, 24, 10, 27, 11, 26},
				{28, 12, 29, 13, 30, 14, 31, 15, 16, 0, 17, 1, 18, 2, 19, 3, 20, 4, 21, 5, 22, 6, 23, 7, 24, 8, 25, 9, 26, 10, 27, 11},
				{13, 28, 12, 29, 15, 30, 14, 31, 1, 16, 0, 17, 3, 18, 2, 19, 5, 20, 4, 21, 7, 22, 6, 23, 9, 24, 8, 25, 11, 26, 10, 27},
				{19, 17, 31, 29, 27, 25, 23, 21, 2, 0, 14, 12, 10, 8, 6, 4, 18, 16, 30, 28, 26, 24, 22, 20, 3, 1, 15, 13, 11, 9, 7, 5},
				{29, 19, 17, 31, 21, 27, 25, 23, 12, 2, 0, 14, 4, 10, 8, 6, 28, 18, 16, 30, 20, 26, 24, 22, 13, 3, 1, 15, 5, 11, 9, 7},
				{31, 29, 19, 17, 23, 21, 27, 25, 14, 12, 2, 0, 6, 4, 10, 8, 30, 28, 18, 16, 22, 20, 26, 24, 15, 13, 3, 1, 7, 5, 11, 9},
				{17, 31, 29, 19, 25, 23, 21, 27, 0, 14, 12, 2, 8, 6, 4, 10, 16, 30, 28, 18, 24, 22, 20, 26, 1, 15, 13, 3, 9, 7, 5, 11},
				{10, 2, 27, 19, 11, 3, 26, 18, 4, 12, 21, 29, 5, 13, 20, 28, 6, 14, 23, 31, 7, 15, 22, 30, 8, 0, 25, 17, 9, 1, 24, 16},
				{19, 10, 2, 27, 18, 11, 3, 26, 29, 4, 12, 21, 28, 5, 13, 20, 31, 6, 14, 23, 30, 7, 15, 22, 17, 8, 0, 25, 16, 9, 1, 24},
				{27, 19, 10, 2, 26, 18, 11, 3, 21, 29, 4, 12, 20, 28, 5, 13, 23, 31, 6, 14, 22, 30, 7, 15, 25, 17, 8, 0, 24, 16, 9, 1},
				{2, 27, 19, 10, 3, 26, 18, 11, 12, 21, 29, 4, 13, 20, 28, 5, 14, 23, 31, 6, 15, 22, 30, 7, 0, 25, 17, 8, 1, 24, 16, 9}
			}};

			static consteval std::array<std::array<uint8_t, 32>, 16> get_n_V() {
				return is_big_endian() ? n_V_big_endian : n_V_little_endian;
			}
	private: 
			// constant array used in the transformation of the key
			uint32_t A[8] = {
				0x184f03e9, 
				0x216c46df,
				0x119f904f,
				0x64997dfd,
				0x2a5497bd,
				0x3918fa83,
				0xaf820335,
				0x85096c2e,
			};
			
			// for modular addition in a Prime Galois Field, field size p, largest 32-bit unsigned prime number
			static const constexpr uint32_t fp = 4294967291; // 0xfffffffb
		
			// rotation index r
			static const constexpr uint8_t r[] = {
				23, 5, 17, 31, 13
			};
		
			// bitwise right rotation
			inline uint32_t rotr(uint32_t x, uint8_t shift)
			{
				return (x >> shift) | (x << ((sizeof(x)<<3)-shift));
			}
		
			// bitwise left rotation
			inline uint32_t rotl(uint32_t x, uint8_t shift)
			{
				return (x << shift) | (x >> ((sizeof(x)<<3)-shift));
			}
		
			// initial key, before any permutation
			uint8_t *init_key;
		
			// dynamically permutate the key during iteration
			// key: permutated 32-byte key
			// p: dynamically re-purmutated key
			// ni: index of dynamic permutation number n
			// ni: iteration index
			void dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni)
			{
				constexpr std::array<std::array<uint8_t, 32>, 16> n_V = get_n_V();
				for(uint32_t i=0;i<keysize;i++) {
					p[i] = key[n_V[ni][i]];
				}
				memcpy(key, p, keysize); // copy the repurmutated values
			}
		
			// iterations for the main transformation loop
			void transformation(uint8_t *key)
			{
				// vector used for dynamic permutation, dynamically permutated key placeholder
				// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
				uint8_t p[keysize];
		
				// 32-bit array ints for key for arithmetic ARX manipulations
				uint32_t *k = reinterpret_cast<uint32_t*>(key); // length of k is 8
		
				// need pre manipulation so that all bytes increase avalanche effect with the same magnitude
				// if all bytes are mixed in to each other by addition
		
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

	public:
		
			const constexpr static uint8_t keysize = 32;

			// key: 256-bit (32-byte) key, should be allocated with length keysize
			void hash(uint8_t *key)
			{
				// transformation iterations
				transformation(key);
		
			}
};


// generate a random 32-byte key
void gen_rand_key(uint8_t *key)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint8_t> dist(0, 0xff);
	for(uint8_t i=0;i<32;i++) key[i] = dist(gen);
}

// calculate the collision rate with random key
double find_collision_rate_random_key(uint32_t n)
{
	double collision_rate = 0;
	uint8_t tmp[32];
	uint8_t initial_key[32];
	uint8_t oldkey[32];
	gen_rand_key(tmp); // initialize a random initial key
	memcpy(oldkey, tmp, 32);
	for(int k=1;k<256;k++) { // calculate average collision rate
		memcpy(initial_key, tmp, 32);
		memcpy(oldkey, tmp, 32);
		FullTimePad fulltimepad1 = FullTimePad();
		FullTimePad fulltimepad2 = FullTimePad();
		initial_key[n] = k;
		oldkey[n] = k-1;

		fulltimepad1.hash(initial_key);
		fulltimepad2.hash(oldkey);
		double temp_rate = 0;
		for(int i=0;i<32;i++) {
			if(initial_key[i] == oldkey[i]) {
				temp_rate++;
			}
		}

		// print the percentage changes when one bit of data is changed in key
		double col = temp_rate/32*100;
		collision_rate += temp_rate;

		if(col < 10)
			std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << col << "%";
		else 
			std::cout << std::dec << std::fixed << std::setprecision(4) << col << "%";
		std::cout << ": n=" << n << "\t";
		if(k%10 == 0) std::cout << std::endl;
	}
	collision_rate/=32*255;
	//for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
	//std::cout << std::endl;
	return collision_rate*100;
}

// calculate the collision rate with incrementing integers key
double find_collision_rate(uint32_t n)
{
	double collision_rate = 0;
	for(int k=1;k<256;k++) {
		uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		uint8_t oldkey[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		FullTimePad fulltimepad1 = FullTimePad();
		FullTimePad fulltimepad2 = FullTimePad();
		initial_key[n] = k;
		oldkey[n] = k-1;

		fulltimepad1.hash(initial_key);
		fulltimepad2.hash(oldkey);
		for(int i=0;i<32;i++) {
			if(initial_key[i] == oldkey[i]) {
				collision_rate++;
			}
		}
	}
	collision_rate/=32*255; // total collision rate
	//for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
	//std::cout << std::endl;
	return collision_rate*100;
}


// find if a particular byte affects collision rate more or less
// print the average  collision rates to test the avalanche effect. Higher collision means lower avalanche effect.
void check_bytes_permutation(CollisionCalculation collision_calc)
{
	double total = 0;
	for(int i=0;i<32;i++) {
		// get collision rate at i'th index of key
		double rate;
		if(collision_calc == random_key) {
			rate = find_collision_rate_random_key(i);

			std::cout << " avr =  ";
			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			std::cout << std::endl << std::endl;
		} else {
			rate = find_collision_rate(i);

			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			if((i+1)%8 == 0) std::cout << std::endl;
		}
		
		total+=rate;
	}
	total/=32;
	std::cout << std::endl << "total: " << total << "%";
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void signal_handler(int sig) {
	doprint = true;
}

int main(int argc, char *argv[])
{
	CollisionCalculation collision_calc;

	// parse user input to determine how the collision calculation should be performed
	if(argc > 1 && strcmp(argv[1], "-r") == 0) {
		collision_calc = random_key;
	} else {
		collision_calc = incrementing_key;
	}

	// catch signal interrupt
	signal(SIGINT, signal_handler);
	check_bytes_permutation(collision_calc);

	std::cout << std::endl;
	return 0;
}
#pragma GCC diagnostic pop

#endif /* BEST_PERMUTATION_CPP */

