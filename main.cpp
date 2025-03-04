#include <stdint.h>

#include "fulltimepad.h"

int main()
{
	uint8_t pt[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t ct[32];
	double collision_rate = 0;

	// update by 1 and test again
	for(int m=1;m<256;m++) {
		uint8_t initial_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		uint8_t oldkey[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
		initial_key[0] = m;
		oldkey[0] = m-1;
		FullTimePad fulltimepad1 = FullTimePad(oldkey);
		fulltimepad1.hash(oldkey);

		FullTimePad fulltimepad = FullTimePad(initial_key);
		fulltimepad.hash(initial_key);
		if(m != 0) {
			double col = 0;
			for(int i=0;i<32;i++) {
				if(initial_key[i] == oldkey[i]) {
					col++;
				}
			}
			col/=32;
			collision_rate += col;
		}
		memcpy(oldkey, initial_key, 32);
		for(int i=0;i<32;i++) std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << initial_key[i]+0 << ", ";
		std::cout << std::endl;
	}
		collision_rate/=255;
	std::cout << std::endl << (collision_rate*100) << "% ";

	
	return 0;
}
