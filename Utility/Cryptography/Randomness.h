#ifndef RANDOMNESS
#define RANDOMNESS

#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

using namespace std;


vector<unsigned char> generateRandomBytes(int length);


#endif // RANDOMNESS
