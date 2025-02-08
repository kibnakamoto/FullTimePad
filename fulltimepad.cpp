/*
 * @Author: Taha
 * Date: Feb 6, 2025
 *
 * TODO: licence, and licence information
 */

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <assert.h>

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

	// indexes represented as constant when rotated V right by n
	static const constexpr uint8_t n_V[][32] = {
	//		{3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30},
	//		{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1},
	//		{5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0},
	//		{7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2},
	//		{9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4},
	//		{13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8},
	//		{15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10},
	//		{19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14},
	//		{21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16},
	//		{25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20},
	//		{31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26},
	//		{1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28},

		// random permutation: less collissions
		//{4, 13, 11, 3, 31, 0, 9, 29, 6, 1, 14, 12, 18, 8, 17, 28, 23, 2, 10, 21, 27, 25, 30, 20, 26, 7, 5, 22, 24, 19, 15, 16},
		//{20, 5, 25, 11, 16, 7, 6, 10, 27, 24, 22, 26, 13, 1, 2, 8, 23, 0, 29, 4, 12, 28, 15, 18, 14, 30, 9, 19, 31, 3, 17, 21}, 
		//{7, 31, 13, 6, 25, 20, 11, 29, 18, 0, 8, 19, 10, 17, 21, 12, 16, 3, 2, 9, 4, 30, 24, 5, 23, 15, 22, 28, 26, 27, 14, 1},
		//{23, 30, 31, 25, 21, 19, 28, 3, 8, 13, 18, 2, 17, 0, 14, 4, 11, 22, 24, 16, 6, 15, 9, 27, 20, 26, 5, 12, 7, 10, 29, 1},
		//{22, 18, 15, 1, 4, 26, 3, 21, 23, 29, 11, 16, 10, 14, 12, 8, 0, 24, 13, 30, 6, 19, 2, 17, 9, 5, 7, 20, 31, 25, 27, 28},
		//{14, 15, 13, 9, 23, 16, 8, 20, 1, 12, 29, 2, 27, 17, 4, 31, 0, 10, 26, 30, 11, 19, 6, 3, 24, 25, 22, 5, 7, 28, 21, 18},
		//{11, 7, 3, 5, 6, 20, 25, 23, 30, 0, 22, 15, 27, 10, 12, 21, 19, 13, 8, 24, 29, 31, 4, 1, 28, 16, 26, 9, 2, 14, 18, 17},
		//{7, 13, 19, 8, 28, 23, 16, 0, 5, 10, 24, 31, 18, 4, 1, 30, 2, 27, 12, 11, 26, 15, 3, 6, 22, 21, 14, 9, 29, 20, 17, 25},
		//{16, 1, 8, 28, 7, 2, 18, 30, 13, 24, 29, 11, 4, 22, 20, 3, 23, 0, 10, 26, 21, 5, 27, 25, 12, 17, 9, 14, 19, 15, 31, 6},
		//{29, 9, 10, 12, 15, 4, 25, 6, 14, 22, 31, 5, 16, 30, 0, 24, 17, 23, 28, 7, 13, 26, 21, 3, 27, 18, 20, 19, 11, 8, 1, 2},
		//{14, 6, 15, 23, 4, 26, 28, 29, 5, 19, 9, 8, 13, 10, 1, 16, 24, 12, 30, 7, 20, 3, 31, 2, 17, 22, 27, 11, 25, 21, 18, 0},
		//{19, 21, 18, 13, 28, 5, 12, 11, 15, 1, 9, 17, 4, 24, 7, 16, 26, 14, 23, 30, 8, 0, 2, 27, 20, 6, 29, 25, 10, 31, 22, 3}


		// ideal permutations: would have 1 byte shifted to each another 32-bit number.
		// e.g. byte 0 goes to byte 4
		//{0, 4, 8, 12, 16, 20, 24, 28, 1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31},
		//{1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0},
		//{2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1},
		//{3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2},
		//{4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3},
		//{5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4},
		//{6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5},
		//{7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6},
		//{8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7},
		//{9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8},
		//{10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9},
		//{11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9, 14, 18, 22, 26, 30, 2, 6, 10}

		// randomly aligned to limit collisions /////////////////// BEST ONE SO FAR
		{0, 4, 8, 12, 16, 20, 24, 28, 1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31},
		{2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1},
		{4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3},
		{1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0},
		{3, 7, 11, 15, 19, 23, 27, 31, 4, 8, 12, 16, 20, 24, 28, 0, 5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2},
		{6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5},
		{5, 9, 13, 17, 21, 25, 29, 1, 6, 10, 14, 18, 22, 26, 30, 2, 7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4},
		{7, 11, 15, 19, 23, 27, 31, 3, 8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6},
		{8, 12, 16, 20, 24, 28, 0, 4, 9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7},
		{11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9, 14, 18, 22, 26, 30, 2, 6, 10},
		{10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8, 13, 17, 21, 25, 29, 1, 5, 9},
		{9, 13, 17, 21, 25, 29, 1, 5, 10, 14, 18, 22, 26, 30, 2, 6, 11, 15, 19, 23, 27, 31, 3, 7, 12, 16, 20, 24, 28, 0, 4, 8},
	};

/* calculated permutation: wanted indexes
[18, 17, 20, 19, 22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15], 
[20, 19, 22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15, 18, 17],
[23, 22, 25, 24, 27, 26, 29, 28, 31, 30, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16, 19, 18, 21, 20],
[28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15, 18, 17, 20, 19, 22, 21, 24, 23, 26, 25],
[3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30, 1, 0],
[14, 13, 16, 15, 18, 17, 20, 19, 22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11],
[27, 26, 29, 28, 31, 30, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16, 19, 18, 21, 20, 23, 22, 25, 24],
[12, 11, 14, 13, 16, 15, 18, 17, 20, 19, 22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9],
[31, 30, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28],
[22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15, 18, 17, 20, 19],
[19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16],
[18, 17, 20, 19, 22, 21, 24, 23, 26, 25, 28, 27, 30, 29, 0, 31, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15],
 */


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
	void dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni)
	{
		for(uint32_t i=0;i<keysize;i++) {
			p[i] = key[n_V[ni][i]];
		}
		memcpy(key, p, keysize); // copy the repurmutated values
	}

	// iterations for the main transformation loop
	void transformation(uint8_t *key) // length of k is 8
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
			dynamic_permutation(key, p, i%nl);
		}
	}

	// safely delete the inital key
	bool terminate_k = false;

	public:
			// if you want the destructor called to safely destroy key after use is over
			// this is to make sure that the key is deleted safely and that the ownership of the init_key isn't managed somewhere else
			inline void terminate() noexcept
			{
				terminate_k = true;
			}

			const constexpr static uint8_t keysize = 32;

			FullTimePad(uint8_t *initial_key)
			{
				init_key = initial_key;
			}

			// key: 256-bit (32-byte) key, should be allocated with length keysize
			void hash(uint8_t *key)
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
			void transform(uint8_t *pt, uint8_t *ct, uint32_t length, uint32_t encryption_index)
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
			~FullTimePad()
			{
				if (terminate_k) {
					memset(init_key, 0, keysize); // set to 0s for a safe memory deletion before deallocation
					delete[] init_key;
				}
			}

};

int main()
{
	uint8_t pt[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t ct[32];
	double collision_rate = 0;
	uint8_t oldkey[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	for(int m=0;m<256;m++) {
		uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		initial_key[0] = m;
		//initial_key[20] = 255-m;
		//initial_key[4] = m-20;
		FullTimePad fulltimepad = FullTimePad(initial_key);
		fulltimepad.hash(initial_key);
		if(m != 0) {
			double col = 0;
			for(int i=0;i<32;i++) {
				if(initial_key[i] == oldkey[i]) {
					col++;
				}
			}
			col/=31;
			collision_rate += col;
		}
		memcpy(oldkey, initial_key, 32);
		//fulltimepad.transform(pt, ct, 32, 0);
		for(int i=0;i<32;i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
		std::cout << std::endl;
	}
		collision_rate/=255;
	std::cout << std::endl << (collision_rate*100) << "% ";

	
	return 0;
}
