#include "Hash.h"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

vector<unsigned char> Hash::computeSHA256(const vector<unsigned char>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD* md = EVP_sha256();
    vector<unsigned char> hash(EVP_MD_size(md));

    if (EVP_DigestInit_ex(ctx, md, nullptr) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("SHA-256 initialization failed");
    }

    // Process the data in chunks
    const size_t CHUNK_SIZE = 4096;  // 4 KB chunk size (can be adjusted)
    size_t processed = 0;
    while (processed < data.size()) {
        size_t chunkSize = min(CHUNK_SIZE, data.size() - processed);
        if (EVP_DigestUpdate(ctx, data.data() + processed, chunkSize) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("SHA-256 update failed");
        }
        processed += chunkSize;
    }

    if (EVP_DigestFinal_ex(ctx, hash.data(), nullptr) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("SHA-256 finalization failed");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

vector<unsigned char> Hash::computeSHA256(const string& data) {
    vector<unsigned char> dataBytes(data.begin(), data.end());
    return computeSHA256(dataBytes);
}

string Hash::toHexString(const vector<unsigned char>& hash) {
    ostringstream oss;
    for (unsigned char byte : hash) {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}
