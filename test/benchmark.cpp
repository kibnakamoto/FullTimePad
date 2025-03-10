#include <iostream>
#include <chrono>
#include <random>

#include "../fulltimepad.h"

// generate a random 32-byte key
void gen_rand_key(uint8_t *key)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint8_t> dist(0, 0xff);
	for(uint8_t i=0;i<32;i++) key[i] = dist(gen);
}

// Check for a potential Side Channel Vulnerability to check if small numbers are faster
template<FullTimePad::Version version>
void benchmark_hash_time_attack_v()
{
	uint8_t *key = new uint8_t[32];
    uint8_t transformed_key[32];
	double speeds[256]; // keep an array of all speeds. Compare after it's done
	for(int i=0;i<256;i++) {
		// assign key to 32 0s to 32 255s
		for(int j=0;j<32;j++) {
			key[j] = i;
		}
		FullTimePad fulltimepad = FullTimePad(key);
    	auto start = std::chrono::high_resolution_clock::now(); // start timing

		// get the average of 100 repetations to get more consistent numbers
		for(int j=0;j<1000;j++) {
			fulltimepad.hash<version>(transformed_key, 0); // key is different each time so encryption index can be the same
		}
    	auto end = std::chrono::high_resolution_clock::now(); // end timing
    	std::chrono::duration<double> timer = end - start; // how long calculation took
		speeds[i] = timer.count()/1000;
	}

	// analyize speed data (check if they are consistent)
	bool consistent = true;
	for(int i=1;i<256;i++) {
		if(round(speeds[i]/speeds[i-1]) != 1)
			consistent = false;
	}

	if(consistent) {
	
		// check for first and last speed.
		if(round(speeds[0]/speeds[255]) != 1)
			consistent = false;

		if(consistent) { // if still consistent
			// However, test if speed were consistently growing: It shouldn't
			double counter=0;
			for(int i=1;i<256;i++) {
				if(speeds[i] > speeds[i-1]) { // if current speed is bigger than previous speed, computation time is increasing as numbers get bigger
					counter++;
				}
			}
			if(round(256/counter) == 2) { // final check, half the time, the speeds should be bigger then previous and vice versa.
				std::cout << "PASSED (NO SIDE CHANNEL): data is consistent " << " \n";
			} else {
				std::cout << "FAILED (POTENTIAL SIDE-CHANNEL): data is increasing consistently " << " \n";
				for(int i=0;i<256;i++) {
					std::cout << speeds[i] << "\t";
				}
			}
		} else {
			std::cout << "FAILED (POTENTIAL SIDE-CHANNEL): first and last data isn\'t consistent\nRATIO (speed[0]/speed[255]):\n";
			std::cout << speeds[0]/speeds[255] << "\t";
		}
	} else {
		std::cout << "FAILED (POTENTIAL SIDE-CHANNEL): data isn\'t consistent\nDATA:\n";
		for(int i=1;i<256;i++) {
			// if this ratio is close to 1, then numbers are about the same and therefore consistent numbers.
			std::cout << speeds[i]/speeds[i-1] << "\t";
		}
	}
	std::cout << std::endl;

	delete[] key;
}


template<FullTimePad::Version version>
void benchmark_hash()
{
	uint8_t *key = new uint8_t[32];
    uint8_t transformed_key[32];
	gen_rand_key(key);

	FullTimePad fulltimepad = FullTimePad(key);

    // Start the clock to measure encryption time
	// call hash function 1,000,000 times
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < 1000000; ++i) {
		fulltimepad.hash<version>(transformed_key, i);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> timer = end - start;
    double speed = 1000000 / timer.count();

    std::cout << "Computation Time for " << 1000000 << " key transformations: "
              << timer.count() << " seconds" << std::endl;
    std::cout << "Hashrate: " << (uint64_t)speed << " keys per second" << std::endl;

	delete[] key;
}

int main()
{
	// test speed of hashing algorithm:
	std::cout << "\n\n----------TESTING SPEED----------";
	std::cout << "\nTESTING TRANSFORMATION VERSION 1.0: ";
	benchmark_hash<FullTimePad::Version10>();
	std::cout << "\nTESTING TRANSFORMATION VERSION 1.1: ";
	benchmark_hash<FullTimePad::Version11>();
	std::cout << "\nTESTING TRANSFORMATION VERSION 2.0: ";
	benchmark_hash<FullTimePad::Version20>();

	/*
	 * Upon further testing, The permutation can be made more efficient by using a uniform permutation matrix rather than a non-uniform permutation matrix. In Other words, instead of placeholder vector, use swapping.
	 * */

	// test for time-based side channel attack possibility:
	std::cout << "\n\n----------TESTING SIDE CHANNEL ATTACKS----------";
	std::cout << "\nTESTING TRANSFORMATION VERSION 1.0: ";
	benchmark_hash_time_attack_v<FullTimePad::Version10>(); // PASSED
	std::cout << "\nTESTING TRANSFORMATION VERSION 1.1: ";
	benchmark_hash_time_attack_v<FullTimePad::Version11>(); // PASSED
	std::cout << "\nTESTING TRANSFORMATION VERSION 2.0: ";
	benchmark_hash_time_attack_v<FullTimePad::Version20>(); // PASSED
	return 0;
}
