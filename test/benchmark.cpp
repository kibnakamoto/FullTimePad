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
    const size_t messageSize = 32;  // 32-byte messages
    const size_t numMessages = 1000000;  // Number of 32-byte messages to encrypt
	
	uint8_t *key = new uint8_t[32];

    // Generate a random key and nonce
	gen_rand_key(key);

    // Create a buffer to hold a single 32-byte message
    uint8_t data[messageSize];

    // Start the clock to measure encryption time
    auto start = std::chrono::high_resolution_clock::now();

	FullTimePad fulltimepad = FullTimePad(key);

    // Encrypt multiple 32-byte messages
    for (size_t i = 0; i < numMessages; ++i) {
		fulltimepad.hash(data);
    }

    // Stop the clock after encryption
    auto end = std::chrono::high_resolution_clock::now();

    // Calculate the time taken in seconds
    std::chrono::duration<double> elapsed = end - start;

    // Calculate how many 32-byte messages were encrypted per second
    double messagesPerSecond = numMessages / elapsed.count();

    std::cout << "Time taken to encrypt " << numMessages << " 32-byte messages: "
              << elapsed.count() << " seconds" << std::endl;
    std::cout << "Encryption rate: " << (uint64_t)messagesPerSecond << " messages per second" << std::endl;

	delete[] key;
}

int main()
{
	benchmark_hash();
	return 0;
}
