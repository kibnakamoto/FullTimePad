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
    	auto start = std::chrono::high_resolution_clock::now(); // start timing
		FullTimePad fulltimepad = FullTimePad(key);

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
		std::cout << "PASSED (NO SIDE CHANNEL): data is consistent\n";
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

    // Start the clock to measure encryption time
    auto start = std::chrono::high_resolution_clock::now();

	// call hash function 1,000,000 times
	FullTimePad fulltimepad = FullTimePad(key);
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
