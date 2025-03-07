/*
 * @Author: Taha
 * Date: March 4, 2025
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

#include <stdint.h>
#include <iostream>
#include <random>
#include <signal.h>
#include <fstream>
#include <sstream>

#include "../fulltimepad.h"

static bool doprint = false; // print highest collision and keys and exit

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void signal_handler(int sig) {
	doprint = true;
}

// test how many bytes of transformed(k1) = transformed(k2). the highest number should be kept.
void test_collision(uint8_t *k1, uint8_t *k2, double &highest_collision)
{
	double collision = 0;
	for(uint8_t i=0;i<FullTimePad::keysize;i++) {
		if(k1[i] == k2[i]) {
			collision++;
		}
	}
	collision/=32; // get the rate
	if(highest_collision < collision) {
		highest_collision = collision;
	}
}

// generate a random 32-byte key (not cryptographically secure but will be enough for testing)
void gen_rand_key(uint8_t *key)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint8_t> dist(0, 0xff);
	for(uint8_t i=0;i<32;i++) key[i] = dist(gen);
}

// brute-force the key by generating 2 random keys
void brute_force_random()
{
	std::ofstream textfile("collision_report.txt");

	uint8_t *k1 = new uint8_t[32];
	uint8_t *k2 = new uint8_t[32];
	double highest_collision = 0; // highest collision rate. If 1 achieved, the encryption algorithm failed to provide security.
	double prev_highest_collision = 0;
	uint64_t iteration = 0; // how many iterations
	while(true) {
		if(doprint) {
			std::stringstream ss;
			ss << std::endl << "\nHighest Collision Rate: " << highest_collision*100 << "%\ti: " << iteration << std::endl;
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;

			// cleanup
			delete[] k1;
			delete[] k2;
			textfile.close();
			exit(0);
		}

		// generate 2 random keys
		gen_rand_key(k1);
		gen_rand_key(k2);

		// generate transformed(key)
		FullTimePad fulltimepad1 = FullTimePad(k1);
		FullTimePad fulltimepad2 = FullTimePad(k2);
		fulltimepad1.hash(k1, 0); // since keys are unieqe each time, encryption index can stay the same
		fulltimepad2.hash(k2, 0);

		test_collision(k1, k2, highest_collision);

		if(highest_collision > prev_highest_collision) {
			std::stringstream ss;
			ss << std::endl << "Higher Collision Rate: " << highest_collision*100 << "%\ti: " << iteration;
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;
		}

		if(highest_collision == 1) {
			std::stringstream ss;
			ss << std::endl << "\nMAJOR PROBLEM: ENCRYPTION ALGORITHM DEFECTIVE --- Collision Rate: " << highest_collision*100 << "%";
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;


			// cleanup
			delete[] k1;
			delete[] k2;
			textfile.close();
			exit(0);
		}

		prev_highest_collision = highest_collision;
		iteration++;
	}
	delete[] k1;
	delete[] k2;
	textfile.close();
}

// brute-force the key by generating 1 random key and incrementing it till it's similiar
void brute_force_incr()
{
	std::ofstream textfile("collision_report.txt");

	uint8_t *k1 = new uint8_t[32];
	uint8_t *transformed_k1 = new uint8_t[32];
	uint8_t *transformed_k2 = new uint8_t[32];
	uint8_t *k2 = new uint8_t[32];
	double highest_collision = 0; // highest collision rate. If 1 achieved, the encryption algorithm failed to provide security.
	double prev_highest_collision = 0;
	uint64_t iteration = 0; // how many iterations

	// generate 2 random keys
	gen_rand_key(k1);
	memcpy(k2, k1, FullTimePad::keysize);

	// generate transformed(k1) once
	FullTimePad fulltimepad1 = FullTimePad(k1);
	fulltimepad1.hash(transformed_k1, 0);

	while(true) {
		if(doprint) {
			std::stringstream ss;
			ss << std::endl << "\nHighest Collision Rate: " << highest_collision*100 << "%\ti: " << iteration << std::endl;
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;

			// cleanup
			delete[] k1;
			delete[] k2;
			delete[] transformed_k1;
			delete[] transformed_k2;
			textfile.close();
			exit(0);
		}

		// increment k2 starting from 0 (64-bits is enough)
		k2[0] = iteration >> 56;
		k2[1] = iteration >> 48;
		k2[2] = iteration >> 40;
		k2[3] = iteration >> 32;
		k2[4] = iteration >> 24;
		k2[5] = iteration >> 16;
		k2[6] = iteration >> 8;
		k2[7] = iteration;

		// generate transformed(k2)
		FullTimePad fulltimepad2 = FullTimePad(k2);
		fulltimepad2.hash(transformed_k2, 0); // testing brute-forcing so encryption index should be same

		// compare the transformed keys
		test_collision(transformed_k1, transformed_k2, highest_collision);

		if(highest_collision > prev_highest_collision) {
			std::stringstream ss;
			ss << std::endl << "Higher Collision Rate: " << highest_collision*100 << "%\ti: " << iteration;
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;
		}

		if(highest_collision == 1) {
			std::stringstream ss;
			ss << std::endl << "\nMAJOR PROBLEM: ENCRYPTION ALGORITHM DEFECTIVE --- Collision Rate: " << highest_collision*100 << "%";
			std::cout << ss.str() << std::flush;
			textfile << ss.str() << std::flush;

			// cleanup
			delete[] k1;
			delete[] k2;
			delete[] transformed_k1;
			delete[] transformed_k2;
			textfile.close();
			exit(0);
		}

		prev_highest_collision = highest_collision;
		iteration++;
	}
	delete[] k1;
	delete[] k2;
	delete[] transformed_k1;
	delete[] transformed_k2;
	textfile.close();
}

int main(int argc, char *argv[])
{
	// catch signal interrupt
	signal(SIGINT, signal_handler);

	// parse user input to determine how the brute-force should be performed (random or incremented)
	if(argc > 1 && strcmp(argv[1], "-r") == 0) {
		brute_force_random();
	} else {
		brute_force_incr();
	}

	return 0;
}
