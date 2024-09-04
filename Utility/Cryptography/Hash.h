#ifndef HASH_H
#define HASH_H

#include <vector>
#include <string>

using namespace std;

class Hash {
public:
    // Computes the SHA-256 hash of the input data.
    static vector<unsigned char> computeSHA256(const vector<unsigned char>& data);

    // Overload for computing SHA-256 of a string
    static vector<unsigned char> computeSHA256(const string& data);

    // Converts the hash to a hexadecimal string for easy readability
    static string toHexString(const vector<unsigned char>& hash);
};

#endif // HASH_H
