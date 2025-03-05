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

// calculate the collision rate with random key
double differential_cryptoanalysis_random_key(uint32_t n, uint8_t range)
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

		fulltimepad1.hash(initial_key);
		fulltimepad2.hash(oldkey);
		double temp_rate = 0;
		for(int i=0;i<32;i++) {
			 if((int)initial_key[i] <= (int)oldkey[i]+range && (int)initial_key[i] >= (int)oldkey[i]-range) { // check if it's in range with accuracy of range
				temp_rate++;
			}
		}

		// print the percentage changes when one bit of data is changed in key
		double col = temp_rate/32*100;
		collision_rate += temp_rate;

		//if(col < 10)
		//	std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << col << "%";
		//else
		//	std::cout << std::dec << std::fixed << std::setprecision(4) << col << "%";
		//std::cout << ": n=" << n << "\t";
		//if(k%10 == 0) std::cout << std::endl;
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
		initial_key[n] = k;
		oldkey[n] = k-1;
		FullTimePad fulltimepad1 = FullTimePad(initial_key);
		FullTimePad fulltimepad2 = FullTimePad(oldkey);

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
	if(collision_calc == random_key) {
		for(int i=0;i<32;i++) {
			// get collision rate at i'th index of key
			double rate = find_collision_rate_random_key(i);

			std::cout << " avr =  ";
			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			std::cout << std::endl << std::endl;

			total+=rate;
		}
		total/=32;
		std::cout << std::endl << "total: " << total << "%";
	} else if(collision_calc == differential_cryptoanalysis) {
		for(uint8_t range=0;range<100;range++) { // inaccuracy range
			total = 0;
			for(int i=0;i<32;i++) {
				// get collision rate at i'th index of key
				double rate = differential_cryptoanalysis_random_key(i, range);

				//std::cout << " avr =  ";
				//if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				//	std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
				//else
				//	std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
				//std::cout << std::endl << std::endl;

				total+=rate;

			}
			total/=32;
			std::cout << "(" << range+0 << ", " << total << ")" << " ";
		}
	} else {
		for(int i=0;i<32;i++) {
			// get collision rate at i'th index of key
			double rate = find_collision_rate(i);

			if (rate < 10) // pad single-digit data with extra zero so it takes the same amount of space on screen (for organization)
				std::cout << std::dec << std::fixed << std::setprecision(4) << '0' << rate << "% : " << i << "\t";
			else
				std::cout << std::dec << std::fixed << rate << "% : " << i << "\t";
			if((i+1)%8 == 0) std::cout << std::endl;

			total+=rate;
		}
		total/=32;
		std::cout << std::endl << "total: " << total << "%";
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
	} else if(argc > 1 && strcmp(argv[1], "-d") == 0) { // differential analysis
		collision_calc = differential_cryptoanalysis;
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

