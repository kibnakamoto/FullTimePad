#include <stdint.h>

#include "fulltimepad.h"

// This is an example file

int main()
{
	uint8_t pt[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t ct[32];
	uint8_t ct_prev[32];
	uint8_t decrypted[32];
	double collision_rate = 0;
	uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint64_t encryption_index = 0;
	FullTimePad fulltimepad = FullTimePad(initial_key);

	// update by 1 and test again, to see collision resistance.
	for(int m=0;m<256;m++) {
		fulltimepad.transform(pt, ct, 32, encryption_index); // encrypt
		if(m != 0) { // don't compare first one
			double col = 0;
			for(int i=0;i<32;i++) {
				if(ct[i] == ct_prev[i]) {
					col++;
				}
			}
			col/=32;
			collision_rate += col;
		}

		// to decrypt:
		fulltimepad.transform(ct, decrypted, 32, encryption_index); // decrypt
		for(int i=0;i<32;i++) {
			if (pt[i] != decrypted[i]) {// this could mean that encryption_index or key is wrong
				std::cout << "FATAL: DECRYPTED CIPHERTEXT NOT EQUAL TO PLAINTEXT";
				exit(0);
			}
		}
		
		memcpy(ct_prev, ct, 32);
		for(int i=0;i<32;i++) std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << ct[i]+0 << ", ";
		std::cout << std::endl;
		encryption_index++; // update encryption index
	}
		collision_rate/=255;
	std::cout << std::endl << (collision_rate*100) << "% ";

	
	return 0;
}
