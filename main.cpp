#include <stdint.h>
#include <fstream>
#include <bitset>

#include "fulltimepad.h"

// This is an example file
// TODO: make the optimization from Version 2.0 for  version 1.0, version 1.1 as well.

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

	//std::ofstream file("test/keystream20", std::ios::binary); // run with the NIST SP 800-22 test suite.
    //for (int i = 0; i < 3907; i++) { // 1 million bits
	//	initial_key[0] = i>>8;
	//	initial_key[1] = i;
	//	fulltimepad.transform<FullTimePad::Version20>(pt, ct, 32, encryption_index); // encrypt

    //	// Convert each byte to 8-bit binary and write to file
    //	for (int j = 0; j < 32; j++) {
    //	    file << std::bitset<8>(ct[j]);  // Convert each byte to an 8-bit string
	//	}

    //	file << "\n";  // Newline after each ciphertext
	//	//encryption_index++;
    //}
    //file.close();

	//exit(0);

	// update by 1 and test again, to see collision resistance.
	for(int m=0;m<256;m++) {
		fulltimepad.transform<FullTimePad::Version20>(pt, ct, 32, encryption_index); // encrypt
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
		fulltimepad.transform<FullTimePad::Version20>(ct, decrypted, 32, encryption_index); // decrypt
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
