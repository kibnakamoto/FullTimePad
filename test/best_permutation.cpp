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
#include <sstream>
#include <vector>
#include <signal.h>
#include <assert.h>
#include <algorithm>
#include <random>
#include <array>
#include <bit>

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
class FullTimePadTest
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
				{15, 11, 7, 3, 31, 27, 23, 19, 14, 10, 6, 2, 30, 26, 22, 18, 13, 9, 5, 1, 29, 25, 21, 17, 12, 8, 4, 0, 28, 24, 20, 16},
				{3, 15, 11, 7, 19, 31, 27, 23, 2, 14, 10, 6, 18, 30, 26, 22, 1, 13, 9, 5, 17, 29, 25, 21, 0, 12, 8, 4, 16, 28, 24, 20},
				{7, 3, 15, 11, 23, 19, 31, 27, 6, 2, 14, 10, 22, 18, 30, 26, 5, 1, 13, 9, 21, 17, 29, 25, 4, 0, 12, 8, 20, 16, 28, 24},
				{11, 7, 3, 15, 27, 23, 19, 31, 10, 6, 2, 14, 26, 22, 18, 30, 9, 5, 1, 13, 25, 21, 17, 29, 8, 4, 0, 12, 24, 20, 16, 28},
				{30, 14, 31, 15, 28, 12, 29, 13, 18, 2, 19, 3, 16, 0, 17, 1, 22, 6, 23, 7, 20, 4, 21, 5, 26, 10, 27, 11, 24, 8, 25, 9},
				{15, 30, 14, 31, 13, 28, 12, 29, 3, 18, 2, 19, 1, 16, 0, 17, 7, 22, 6, 23, 5, 20, 4, 21, 11, 26, 10, 27, 9, 24, 8, 25},
				{31, 15, 30, 14, 29, 13, 28, 12, 19, 3, 18, 2, 17, 1, 16, 0, 23, 7, 22, 6, 21, 5, 20, 4, 27, 11, 26, 10, 25, 9, 24, 8},
				{14, 31, 15, 30, 12, 29, 13, 28, 2, 19, 3, 18, 0, 17, 1, 16, 6, 23, 7, 22, 4, 21, 5, 20, 10, 27, 11, 26, 8, 25, 9, 24},
				{16, 18, 28, 30, 24, 26, 20, 22, 1, 3, 13, 15, 9, 11, 5, 7, 17, 19, 29, 31, 25, 27, 21, 23, 0, 2, 12, 14, 8, 10, 4, 6},
				{30, 16, 18, 28, 22, 24, 26, 20, 15, 1, 3, 13, 7, 9, 11, 5, 31, 17, 19, 29, 23, 25, 27, 21, 14, 0, 2, 12, 6, 8, 10, 4},
				{28, 30, 16, 18, 20, 22, 24, 26, 13, 15, 1, 3, 5, 7, 9, 11, 29, 31, 17, 19, 21, 23, 25, 27, 12, 14, 0, 2, 4, 6, 8, 10},
				{18, 28, 30, 16, 26, 20, 22, 24, 3, 13, 15, 1, 11, 5, 7, 9, 19, 29, 31, 17, 27, 21, 23, 25, 2, 12, 14, 0, 10, 4, 6, 8},
				{9, 1, 24, 16, 8, 0, 25, 17, 7, 15, 22, 30, 6, 14, 23, 31, 5, 13, 20, 28, 4, 12, 21, 29, 11, 3, 26, 18, 10, 2, 27, 19},
				{16, 9, 1, 24, 17, 8, 0, 25, 30, 7, 15, 22, 31, 6, 14, 23, 28, 5, 13, 20, 29, 4, 12, 21, 18, 11, 3, 26, 19, 10, 2, 27},
				{24, 16, 9, 1, 25, 17, 8, 0, 22, 30, 7, 15, 23, 31, 6, 14, 20, 28, 5, 13, 21, 29, 4, 12, 26, 18, 11, 3, 27, 19, 10, 2},
				{1, 24, 16, 9, 0, 25, 17, 8, 15, 22, 30, 7, 14, 23, 31, 6, 13, 20, 28, 5, 12, 21, 29, 4, 3, 26, 18, 11, 2, 27, 19, 10},
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
			void dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni, uint8_t **best_n_V)
			{
				for(uint8_t i=0;i<keysize;i++) {
					p[i] = key[best_n_V[ni][i]];
				}
				memcpy(key, p, keysize); // copy the repurmutated values
			}

			// convert uint8_t *key into uint32_t *k in big endian
			static uint32_t *endian_8_to_32_arr(uint8_t *key)
			{
				if constexpr(!is_big_endian()) {
				    for (uint8_t i=0;i<FullTimePadTest::keysize;i+=4) {
			       		std::swap(key[i], key[i+3]);
			       		std::swap(key[i+1], key[i+2]);
			    	}
				}
					return reinterpret_cast<uint32_t*>(key);
			}
		
			// iterations for the main transformation loop
			void transformation(uint8_t *key, uint8_t **best_n_V) // length of k is 8
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
					dynamic_permutation(key, p, i, best_n_V);
				}
		
			}

	public:
			const constexpr static uint8_t keysize = 32;

			// key: 256-bit (32-byte) key, should be allocated with length keysize
			void hash(uint8_t *key, uint8_t **best_n_V)
			{
				// transformation iterations
				transformation(key, best_n_V);

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
double find_collision_rate_random_key(uint8_t **best_n_V)
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
		FullTimePadTest fulltimepad1 = FullTimePadTest();
		FullTimePadTest fulltimepad2 = FullTimePadTest();
		initial_key[0] = k;
		oldkey[0] = k-1;

		fulltimepad1.hash(initial_key, best_n_V);
		fulltimepad2.hash(oldkey, best_n_V);
		double temp_col = 0;
		for(int i=0;i<32;i++) {
			if(initial_key[i] == oldkey[i]) {
				temp_col++;
			}
		}
		
		// print the percentage changes when one bit of data is changed in key
		double col = temp_col/32*100;
		collision_rate += temp_col;
		if(col < 10)
			std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << col << "%\t";
		else 
			std::cout << std::dec << std::fixed << std::setprecision(4) << col << "%\t";
		if(k%10 == 0) std::cout << std::endl;
	}
	collision_rate/=32*255;
	//for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
	//std::cout << std::endl;
	return collision_rate*100;
}

// calculate the collision rate with incrementing integers key
double find_collision_rate(uint8_t **best_n_V)
{
	double collision_rate = 0;
	for(int k=1;k<2;k++) {
		uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		uint8_t oldkey[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		FullTimePadTest fulltimepad1 = FullTimePadTest();
		FullTimePadTest fulltimepad2 = FullTimePadTest();
		initial_key[0] = k;
		oldkey[0] = k-1;

		fulltimepad1.hash(initial_key, best_n_V);
		fulltimepad2.hash(oldkey, best_n_V);
		for(int i=0;i<32;i++) {
			if(initial_key[i] == oldkey[i]) {
				collision_rate++;
			}
		}
	}
	collision_rate/=32*1;
	//for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
	//std::cout << std::endl;
	return collision_rate*100;
}



// permutate the matrix n_V by swapping indexes with new ones
void permutate_matrix(uint8_t **n_V, uint8_t **placeholder, std::vector<uint8_t> index)
{
	// permutate matrix
	for(uint8_t i=0;i<12;i++) {
		for(uint8_t j=0;j<32;j++) {
			placeholder[i][j] = n_V[index[i]][j];
		}
	}

	// copy the values back from the placeholder
	for(uint8_t i=0;i<12;i++)
		memcpy(n_V[i], placeholder[i], 32);
}

// print the best n_V matrix
void print_best_n_V(uint8_t **n_V)
{
	std::cout << "\nbest n_V: {";
	for(int i=0;i<12;i++) {
		std::cout << "\n\t{" << std::dec;
		for(int j=0;j<32;j++) {
			std::cout << n_V[i][j]+0;
			if(j != 31) std::cout << ", ";
		}
		std::cout << "}";
		if (i != 11) std::cout << ",";
	}
	std::cout << "\n}";
}

// find the best n_V
void new_n_V(uint8_t **n_V, uint8_t **placeholder, double &best_collision_rate, uint32_t &permutations_count, CollisionCalculation collision_calc)
{
    std::vector<uint8_t> index = {0,1,2,3,4,5,6,7,8,9,10,11}; // index of n_V

    do {
		// find collision rate
		double collision_rate;
		if(collision_calc == incrementing_key)
			collision_rate = find_collision_rate(n_V);
		else
			collision_rate = find_collision_rate_random_key(n_V);


		// permutate the matrix
		permutate_matrix(n_V, placeholder, index);

        // Update the best permutation if a lower collision rate is found
        if (collision_rate < best_collision_rate) {
            best_collision_rate = collision_rate;
			std::cout << "new best collision rate: " << best_collision_rate << "%";
			print_best_n_V(n_V);
			std::cout << "\npermutations_count: " << permutations_count << "\n";
        }

		// if exited program
		if (doprint) {
			std::cout << "\n\nbest collision rate: " << best_collision_rate << "%";
			print_best_n_V(n_V);
			std::cout << "\npermutations_count: " << permutations_count << "\n";

			// safely deallocate before exit
			for(uint8_t i=0;i<12;i++) {
				delete[] n_V[i];
				delete[] placeholder[i];
			}
			delete[] n_V;
			delete[] placeholder;
			exit(0);
		}

		permutations_count++;
    } while (std::next_permutation(index.begin(), index.end()));
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void signal_handler(int sig) {
	doprint = true;
}

int main(int argc, char *argv[])
{
	std::cout << "\n----------DEPRECATED FILE - NO LONGER NEEDED AS CONFUSION AND DIFFUSION ARE ALREADY MAXIMIZED----------\n\n";
	CollisionCalculation collision_calc;

	// parse user input to determine how the collision calculation should be performed
	if(argc > 1 && strcmp(argv[1], "-r") == 0) { // for random key: run with ./best_permutation -r
		collision_calc = random_key;
	} else {
		collision_calc = incrementing_key; // for incrementing key (pattern): run with ./best_permutation
	}

	double best_collision_rate = UINT32_MAX;
	uint32_t permutations_count = 0; // number of permutations tried
	uint8_t **n_V = new uint8_t*[16];
	uint8_t **placeholder = new uint8_t*[16];
	constexpr std::array<std::array<uint8_t, 32>, 16> n_V_const = FullTimePadTest::get_n_V();
	for(uint8_t i=0;i<16;i++) {
		n_V[i] = new uint8_t[32];
   		placeholder[i] = new uint8_t[32];
		memcpy(n_V[i], &n_V_const[i][0], 32);
	}
	// catch signal interrupt
	signal(SIGINT, signal_handler);
	new_n_V(n_V, placeholder, best_collision_rate, permutations_count, collision_calc);

	for(uint8_t i=0;i<16;i++) {
		delete[] n_V[i];
		delete[] placeholder[i];
	}
	delete[] n_V;
	delete[] placeholder;
	std::cout << std::endl << "PROGRAM FINSIHED, ALL PERMUTATIONS TRIED";
	return 0;
}
#pragma GCC diagnostic pop

#endif /* BEST_PERMUTATION_CPP */
