#ifndef RANDOMNESS_H
#define RANDOMNESS_H

#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

using namespace std;

vector<unsigned char> generateRandomBytes(int length);

#endif // RANDOMNESS_H
