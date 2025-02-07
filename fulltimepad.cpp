/*
 * @Author: Taha
 * Date: Feb 6, 2025
 *
 * TODO: licence, and licence information
 */

#include <iostream>
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
		{3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30}, 
		{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1}, 
		{5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0}, 
		{7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2}, 
		{9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4}, 
		{13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8}, 
		{15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10}, 
		{19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14}, 
		{21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16}, 
		{25, 22, 27, 24, 29, 26, 31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20}, 
		{31, 28, 1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26}, 
		{1, 30, 3, 0, 5, 2, 7, 4, 9, 6, 11, 8, 13, 10, 15, 12, 17, 14, 19, 16, 21, 18, 23, 20, 25, 22, 27, 24, 29, 26, 31, 28}
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

	public:
			const constexpr static uint8_t keysize = 32;

			FullTimePad(uint8_t *initial_key)
			{
				init_key = initial_key;
			}

			

			// key: 256-bit (32-byte) key, should be allocated with length keysize
			void hash(uint8_t *key, uint32_t encryption_index)
			{

				// make copy of key to transform and to preserve init_key
				memcpy(key, init_key, keysize);

				// permutate the key based on the V array
				static_permutation(key);

				// transformation iterations
				transformation(key);

			}

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
				uint8_t p[keysize];

				// 32-bit array ints for key for arithmetic ARX manipulations
				uint32_t *k = reinterpret_cast<uint32_t*>(key);
				for(uint8_t i=0;i<nl;i++) { // nl is 12, number of primes till keysize (m)
					uint8_t index = i<<1;
					uint8_t i1mod = index % 8;
					uint8_t i2mod = (index+1) % 8;
					uint8_t rmod = i % 5; // 5 rotation values
					k[i1mod] = ( ((uint64_t)k[i1mod] + A[i1mod]) % (fp+0)) ^ rotr(k[i1mod], r[rmod]);
					k[i2mod] = ( ((uint64_t)k[i2mod] + A[i2mod]) % fp) ^ lotr(k[i2mod], r[rmod]); // TODO: uint64_t conversion after testing is over, this is to make sure there is no unwanted overflow
					
					// permutate the bytearray key
					dynamic_permutation(key, p, i%nl);
				}
			}
};

int main()
{
	uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	FullTimePad fulltimepad = FullTimePad(initial_key);
	for(int i=0;i<32;i++) std::cout << initial_key[i]+0 << ", ";

	std::cout << std::endl;
	
	return 0;
}
