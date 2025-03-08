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

#ifndef FULLTIMEPAD_H
#define FULLTIMEPAD_H

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <assert.h>
#include <bit>
#include <array>

// check endiannes before assigning n_V to big/little endian version
static consteval bool is_big_endian() {
	return std::endian::native == std::endian::big;
}

// 256-bit Full-Time-Pad Cipher
class FullTimePad
{

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

			static consteval std::array<std::array<uint8_t, 32>, 16> get_n_V();

	public:
			// select version in transformation function
			enum Version {
				Version10 = 10, // Version 1.0 - Most complexity, less speed
				Version11 = 11, // Version 1.1 - Less complexity, more speed
				Version20 = 20 // Version 2.0 - less complexity, most speed -- preffered to version 1.1 as galois field doesn't affect everything as much as anticipated
			};

	private: 
			// constant array used in the transformation of the key
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
			
			// for modular addition in a Prime Galois Field, field size p, largest 32-bit unsigned prime number
			static const constexpr uint32_t fp = 4294967291; // 0xfffffffb
		
			/*
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
				//{19, 21, 18, 13, 28, 5, 12, 11, 15, 1, 9, 17, 4, 24, 7, 16, 26, 14, 23, 30, 8, 0, 2, 27, 20, 6, 29, 25, 10, 31, 22, 3},
				//{0, 30, 14, 3, 28, 7, 23, 25, 1, 12, 2, 9, 5, 21, 31, 10, 16, 11, 17, 24, 6, 4, 29, 19, 8, 13, 27, 22, 18, 26, 15, 20},
				//{24, 15, 8, 3, 13, 6, 1, 17, 28, 0, 23, 14, 30, 25, 19, 12, 9, 20, 16, 2, 21, 22, 31, 18, 7, 29, 4, 27, 11, 26, 5, 10},
				//{20, 4, 21, 27, 12, 15, 9, 26, 8, 13, 19, 28, 25, 10, 22, 16, 23, 5, 7, 6, 17, 11, 24, 14, 3, 2, 1, 29, 30, 18, 0, 31},
				//{27, 1, 18, 30, 20, 17, 21, 9, 0, 4, 8, 12, 31, 14, 10, 2, 5, 11, 3, 6, 22, 19, 13, 16, 28, 26, 15, 23, 24, 25, 7, 29}
			};
*/
		
			/* calculated permutation: wanted indexes (old)
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
		
			// rotation index r
			static const constexpr uint8_t r[] = {
				23, 5, 17, 31, 13
			};

			// bitwise right rotation
			static inline uint32_t rotr(uint32_t x, uint8_t shift) {
				return (x >> shift) | (x << ((sizeof(x) << 3) - shift));
			}
			
			// bitwise left rotation
			static inline uint32_t rotl(uint32_t x, uint8_t shift) {
			    return (x << shift) | (x >> ((sizeof(x) << 3) - shift));
			}
		
			// initial key, before any permutation
			uint8_t *init_key;

			// placeholder transformed key
			uint8_t *transformed_key;
		
			// safely delete the inital key
			bool terminate_k = false;
			
			// iterations for the main transformation loop
			template<Version version=Version10>
			void transformation(uint8_t *key); // length of k is 8
		
			// dynamically permutate the key during iteration
			// key: permutated 32-byte key
			// p: dynamically re-purmutated key
			// ni: index of dynamic permutation number n
			// ni: iteration index
			static void dynamic_permutation(uint8_t *key, uint8_t *p, uint8_t ni);
			
			// convert uint8_t *key into uint32_t *k in big endian
			static uint32_t *endian_8_to_32_arr(uint8_t *key);


	public:
			// for testing purposes
			#ifdef REVERSE_CPP
			template<Version version>
			friend void inv_transformation(uint8_t *transformed_k);
			#endif

			// if you want the destructor called to safely destroy key after use is over
			// this is to make sure that the key is deleted safely and that the ownership of the init_key isn't managed somewhere else
			inline void terminate() noexcept;

			const constexpr static uint8_t keysize = 32;

			FullTimePad(uint8_t *initial_key);

			// key: 256-bit (32-byte) key, should be allocated with length keysize
			template<Version version=Version10>
			void hash(uint8_t *key, uint64_t encryption_index_nonce);

			// encrypt/decrypt
			// key is the initial key, return heap allocated key output
			// pt: plaintext data
			// ct: ciphertext data
			// length: length of pt, and ct
			// encryption_index: each encrypted value needs it's own encryption index to keep keys unieqe and to avoid collisions
			template<Version version=Version10>
			void transform(uint8_t *pt, uint8_t *ct, uint32_t length, uint64_t encryption_index);

			// Destructor
			~FullTimePad();
};

#endif /* FULLTIMEPAD_H */
