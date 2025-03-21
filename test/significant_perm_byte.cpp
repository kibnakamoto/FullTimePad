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

#include "../fulltimepad.h"

// print best permutation matrix after signal interrupt
static bool doprint = false;

// how the collision calculation should be performed
enum CollisionCalculation {
	incrementing_key,
	random_key,
	differential_cryptoanalysis
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
template<FullTimePad::Version version>
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
		initial_key[n] = k;
		oldkey[n] = k-1;
		FullTimePad fulltimepad1 = FullTimePad(initial_key);
		FullTimePad fulltimepad2 = FullTimePad(oldkey);

		fulltimepad1.hash<version>(initial_key, 0);
		fulltimepad2.hash<version>(oldkey, 0);
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

// calculate the collision rate with random key
template<FullTimePad::Version version>
double differential_cryptoanalysis_random_key(uint32_t n, uint8_t range)
{
	double collision_rate = 0;
	uint8_t initial_key[32];
	uint8_t oldkey[32];
	uint8_t tmp[32];
	gen_rand_key(tmp); // initialize a random initial key
	//uint8_t tmp[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	memcpy(oldkey, tmp, 32);
	for(int k=1;k<256;k++) { // calculate average collision rate
		memcpy(initial_key, tmp, 32);
		memcpy(oldkey, tmp, 32);
		initial_key[n] = k;
		oldkey[n] = k-1;
		FullTimePad fulltimepad1 = FullTimePad(initial_key);
		FullTimePad fulltimepad2 = FullTimePad(oldkey);

		fulltimepad1.hash<version>(initial_key, 0);
		fulltimepad2.hash<version>(oldkey, 0);
		double temp_rate = 0;
		for(int i=0;i<32;i++) {
			 if((int)initial_key[i] <= (int)oldkey[i]+range && (int)initial_key[i] >= (int)oldkey[i]-range) { // check if it's in range with accuracy of range
				temp_rate++;
			}
		}

		// print the percentage changes when one bit of data is changed in key
		double col = temp_rate/32*100;
		collision_rate += col;

		//if(col < 10)
		//	std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << col << "%";
		//else
		//	std::cout << std::dec << std::fixed << std::setprecision(4) << col << "%";
		//std::cout << ": n=" << n << "\t";
		//if(k%10 == 0) std::cout << std::endl;
	}
	collision_rate/=255;
	//for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
	//std::cout << std::endl;
	return collision_rate;
}


// calculate the collision rate with incrementing integers key
template<FullTimePad::Version version>
double find_collision_rate(uint32_t n)
{
	double collision_rate = 0;
	for(int k=1;k<256;k++) {
		uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		uint8_t oldkey[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		initial_key[n] = k;
		oldkey[n] = k-1;
		FullTimePad fulltimepad1 = FullTimePad(initial_key);
		FullTimePad fulltimepad2 = FullTimePad(oldkey);

		fulltimepad1.hash<version>(initial_key, 0);
		fulltimepad2.hash<version>(oldkey, 0);
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
template<FullTimePad::Version version>
void check_bytes_permutation(CollisionCalculation collision_calc)
{
	double total = 0;
	uint32_t fail_count=0; // rate is reasonable for all bytes. (smaller than 0.6% collision suggests secure, this is known as secure hashing algorithm has the same range)
	if(collision_calc == random_key) {
		for(int i=0;i<32;i++) {
			// get collision rate at i'th index of key
			double rate = find_collision_rate_random_key<version>(i);

			std::cout << " avr =  ";
			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			if(rate < 0.6) {
				std::cout << "PASSED";
			} else {
				std::cout << "FAILED";
				fail_count++; // algorithm probably failed security, there can be a few exceptions rarely as it's statistical.
			}
			std::cout << std::endl << std::endl;

			total+=rate;
		}
		total/=32;
		std::cout << std::endl << "total: " << total << "%";
		if(fail_count != 0) {
			double fail_rate = (double)fail_count/32*100;
			std::cout << "\nTHERE ARE " << fail_count << " COUNTS OF HIGH COLLISIONS (" << fail_rate << "% fail rate)";
			if (fail_count < 2) {
				std::cout << "\t | LOW FAIL RATE";
			} else { // more than 1
				std::cout << "\t | HIGH FAIL RATE";
			}
		}
	} else if(collision_calc == differential_cryptoanalysis) {
		for(uint16_t range=0;range<256;range++) { // inaccuracy range
			total = 0;
			double prev = 0;
			double prev_rate = 0;
			for(int i=0;i<32;i++) {
				// get collision rate at i'th index of key
				double rate = differential_cryptoanalysis_random_key<version>(i, range);

				// std::cout << " avr =  ";
				// if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				// 	std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
				// else
				// 	std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
				// std::cout << std::endl << std::endl;
				
				// check if rates are consistently increasing
				double rate_of_rate=1;
				if(prev != 0) {
					double rate_of_rate = rate/prev;
					if(!(rate_of_rate < prev_rate+2 && rate_of_rate > prev_rate-2)) {
						fail_count++;
						std::cout << rate_of_rate << "\t " << prev_rate;;
					}
				}
				prev_rate = rate_of_rate;
				total+=rate;
				prev = rate;
			}
			total/=32;
			//std::cout << "(accuracy range, collision rate): (" << range+0 << ", " << total << ")" << "\n";
			//std::cout << "(" << range+0 << ", " << total << ")" << " ";
			std::cout << total << ", ";
			if(range == 127) std::cout << "\n";

			if(fail_count != 0) {
				std::cout << "\nTHERE ARE " << fail_count << " COUNTS OF INCONSISTENT CHANGES IN RATES (" << (fail_count<2 ? "LOW CHANCE OF" : "CHANCE OF") << " POTENTIAL STATISTICAL PATTERN)";
			}
		}
	} else {
		for(int i=0;i<32;i++) {
			// get collision rate at i'th index of key
			double rate = find_collision_rate<version>(i);

			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			if((i+1)%8 == 0) std::cout << std::endl;
			if(rate >= 0.6) {
				fail_count++; // algorithm probably failed security, there can be a few exceptions rarely as it's statistical.
			}

			total+=rate;
		}
		total/=32;
		std::cout << std::endl << "total: " << total << "%";
		if(fail_count != 0) {
			double fail_rate = (double)fail_count/32*100;
			std::cout << "\nTHERE ARE " << fail_count << " COUNTS OF HIGH COLLISIONS (" << fail_rate << "% fail rate)";
			if (fail_count < 2) {
				std::cout << "\t | LOW FAIL RATE";
			} else { // more than 1
				std::cout << "\t | HIGH FAIL RATE";
			}
		}
	}
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
		std::cout << "\nRUNNING RANDOM KEY - ";
	} else if(argc > 1 && strcmp(argv[1], "-d") == 0) { // differential analysis
		std::cout << "\nRUNNING DIFFERENTIAL CRYPTOANALYSIS - ";
		collision_calc = differential_cryptoanalysis;
	} else {
		std::cout << "\nRUNNING INCREMENTING KEY - ";
		collision_calc = incrementing_key;
	}

	// catch signal interrupt
	signal(SIGINT, signal_handler);
	if ((argc > 1 && strcmp(argv[1], "-2.0") == 0) || (argc > 2 && strcmp(argv[2], "-2.0") == 0)) {
		std::cout << "TRANSFORMATION ALGORITHM 2.0\n";
		check_bytes_permutation<FullTimePad::Version20>(collision_calc);
	} else if((argc > 1 && strcmp(argv[1], "-1.1") == 0) || (argc > 2 && strcmp(argv[2], "-1.1") == 0)) {
		std::cout << "TRANSFORMATION ALGORITHM 1.1\n";
		check_bytes_permutation<FullTimePad::Version11>(collision_calc);
	} else { // Defaults to transformation version 1.0
		std::cout << "TRANSFORMATION ALGORITHM 1.0\n";
		check_bytes_permutation<FullTimePad::Version10>(collision_calc);
	}

	// To run with random keys (no patterns in input):
	// Use ./significant_perm_byte -r -2.0
	// Use ./significant_perm_byte -r -1.1
	// Use ./significant_perm_byte -r -1.0 or just ./collision -r
	// where the number denotes version of transformation algorithm
	// For non-random keys, remove -r

	std::cout << std::endl;
	return 0;
}
#pragma GCC diagnostic pop

#endif /* BEST_PERMUTATION_CPP */

