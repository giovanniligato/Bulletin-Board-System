#include "Randomness.h"

vector<unsigned char> generateRandomBytes(int length) {
    // Create a vector to hold the random bytes
    vector<unsigned char> randomBytes(length);

    // Use OpenSSL's RAND_bytes to generate cryptographically secure random bytes
    if (1 != RAND_bytes(randomBytes.data(), length)) {
        throw runtime_error("Failed to generate random bytes");
    }

    return randomBytes;
}
