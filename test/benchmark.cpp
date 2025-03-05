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
		fulltimepad.hash(transformed_key);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> timer = end - start;
    double messagesPerSecond = 1000000 / timer.count();

    std::cout << "Computation Time for " << 1000000 << " key transformations: "
              << timer.count() << " seconds" << std::endl;
    std::cout << "Hashrate: " << (uint64_t)messagesPerSecond << " keys per second" << std::endl;

	delete[] key;
}

int main()
{
	benchmark_hash();
	return 0;
}
