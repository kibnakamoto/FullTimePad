/*
 * @Author: Taha
 * Date: Feb 6, 2025
 *
 * TODO: licence, and licence information
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

bool doprint = false;

// 256-bit Full-Time-Pad Cipher
class FullTimePad
{
	// constant array used in the transformation of the key
	static const constexpr uint32_t A[] = {
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

	// static permutation vector V
	static const constexpr uint8_t V[] = {
		17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30,
		 1,  0,  3,  2,  5,  4,  7,  6,  9,  8, 11, 10, 13, 12, 15, 14
	};


	// dynamic permutation number n
	static const constexpr uint8_t nl = 12; // number of primes till keysize (m). represented by l
	static const constexpr uint8_t n[nl] = {
		1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31
	};

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
	inline uint32_t lotr(uint32_t x, uint8_t shift)
	{
		return (x << shift) | (x >> ((sizeof(x)<<3)-shift));
	}

	// initial key, before any permutation
	uint8_t *init_key;

	// initial static permutation of the key
	// key: initial key before any permutations
	void static_permutation(uint8_t *key)
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
	void dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni, uint8_t **best_n_V)
	{
		for(uint32_t i=0;i<keysize;i++) {
			p[i] = key[best_n_V[ni][i]];
		}
		memcpy(key, p, keysize); // copy the repurmutated values
	}

	// iterations for the main transformation loop
	void transformation(uint8_t *key, uint8_t **best_n_V) // length of k is 8
	{
		// vector used for dynamic permutation, dynamically permutated key placeholder
		// use stack memory but for really large nubmer of encryptions performed at once, it might be too much for stack, but that is very unlikely.
		uint8_t p[keysize]; // TODO: maybe make it a pointer

		// 32-bit array ints for key for arithmetic ARX manipulations
		uint32_t *k = reinterpret_cast<uint32_t*>(key);
		for(uint8_t i=0;i<nl;i++) { // nl is 12, number of primes till keysize (m)
			uint8_t index = i<<1;
			uint8_t i1mod = index % 8;
			uint8_t i2mod = (index+1) % 8;
			uint8_t rmod = i % 5; // 5 rotation values
			k[i1mod] = ( ((uint64_t)k[i1mod] + A[i1mod]) % fp) ^ rotr(k[i1mod], r[rmod]);
			k[i2mod] = ( ((uint64_t)k[i2mod] + A[i2mod]) % fp) ^ lotr(k[i2mod], r[rmod]); // TODO: uint64_t conversion after testing is over, this is to make sure there is no unwanted overflow
			//std::cout << k[i1mod] << " : " << k[i2mod] << "\n";
			
			// permutate the bytearray key
			dynamic_permutation(key, p, i%nl, best_n_V);
		}
	}

	public:

	// indexes represented as constant when rotated V right by n
	static const constexpr uint8_t n_V[][32] = {
		// ideal permutations: would have 1 byte shifted to each another 32-bit number.
		// e.g. byte 0 goes to byte 4
		{0, 4, 8, 12, 16, 20, 24, 28, 1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31},
		{1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0},
		{2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1},
		{3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2},
		{4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3},
		{5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4},
		{6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5},
		{7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6},
		{8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7},
		{9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8},
		{10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9},
		{11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9, 14, 18, 22, 26, 30, 2, 6, 10}
	};


			const constexpr static uint8_t keysize = 32;
			// key: 256-bit (32-byte) key, should be allocated with length keysize
			void hash(uint8_t *key, uint8_t **best_n_V)
			{
				// transformation iterations
				transformation(key, best_n_V);

			}
};

double find_collision_rate(uint8_t **best_n_V)
{
	double collision_rate = 0;
	uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t oldkey[]      = {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	FullTimePad fulltimepad1 = FullTimePad();
	FullTimePad fulltimepad2 = FullTimePad();
		fulltimepad1.hash(initial_key, best_n_V);
		fulltimepad2.hash(initial_key, best_n_V);
		for(int i=0;i<32;i++) {
			if(initial_key[i] == oldkey[i]) {
				collision_rate++;
			}
		}
		collision_rate/=31;
		//fulltimepad.transform(pt, ct, 32, 0);
		for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
		std::cout << std::endl;
	return collision_rate;
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

// find the best n_V
void new_n_V(uint8_t **n_V, uint8_t **placeholder, double &best_collision_rate, uint32_t &permutations_count)
{
    std::vector<uint8_t> index = {0,1,2,3,4,5,6,7,8,9,10,11}; // index of n_V

    do {
		// find collision rate
        double collision_rate = find_collision_rate(n_V);

		// permutate the matrix
		permutate_matrix(n_V, placeholder, index);

        // Update the best permutation if a lower collision rate is found
        if (collision_rate < best_collision_rate) {
            best_collision_rate = collision_rate;
			std::cout << "new best collision rate: " << best_collision_rate << "\nbest n_V: {";
			for(int i=0;i<12;i++) {
				std::cout << "\n\t{";
				for(int j=0;j<32;j++) {
					std::cout << n_V[i][j]+0;
					if(j != 31) std::cout << ", ";
				}
				std::cout << "}";
				if (i != 11) std::cout << ",";
			}
			std::cout << "\n}";
			std::cout << "\npermutations_count: " << permutations_count << "\n";
        }
		permutations_count++;
    } while (std::next_permutation(index.begin(), index.end()));
}

void signal_handler(sig_atomic_t doprint) {
	doprint = true;
}

int main()
{
	// catch signal interrupt
    signal(SIGINT, signal_handler);

	double best_collision_rate = 0;
	uint32_t permutations_count = 0; // number of permutations tried
	uint8_t **n_V = new uint8_t*[12];
	uint8_t **placeholder = new uint8_t*[12];
	for(uint8_t i=0;i<12;i++) {
		n_V[i] = new uint8_t[32];
   		placeholder[i] = new uint8_t[i];
		memcpy(n_V[i], FullTimePad::n_V[i], 32);
	}
	new_n_V(n_V, placeholder, best_collision_rate, permutations_count);

	// print if exited program
	if (doprint) {
		std::cout << "best collision rate: " << best_collision_rate << "\nbest n_V: {";
		for(int i=0;i<12;i++) {
			std::cout << "\n\t{";
			for(int j=0;j<32;j++) {
				std::cout << n_V[i][j]+0;
				if(j != 31) std::cout << ", ";
			}
			std::cout << "}";
			if (i != 11) std::cout << ",";
		}
		std::cout << "\n}";
		std::cout << "\npermutations_count: " << permutations_count << "\n";
	}

	for(uint8_t i=0;i<12;i++) {
		delete[] n_V[i];
		delete[] placeholder;
	}
	delete[] n_V;
	return 0;
}

#endif /* BEST_PERMUTATION_CPP */
