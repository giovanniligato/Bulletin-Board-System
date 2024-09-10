#ifndef AESGCM_WRAPPER_H
#define AESGCM_WRAPPER_H

#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

class AESGCMWrapper {
public:
    
    // Encrypts the plaintext using AES-GCM with a provided key
    static void encrypt(const vector<unsigned char>& key, 
                        const vector<unsigned char>& plaintext, 
                        vector<unsigned char>& ciphertext,
                        vector<unsigned char>& iv,
                        vector<unsigned char>& tag,
                        const vector<unsigned char>& aad = vector<unsigned char>());

    // Decrypts the ciphertext using AES-GCM with a provided key
    static vector<unsigned char> decrypt(const vector<unsigned char>& key, 
                                         const vector<unsigned char>& ciphertext,
                                         const vector<unsigned char>& iv,
                                         const vector<unsigned char>& tag,
                                         const vector<unsigned char>& aad = vector<unsigned char>());

private:
    AESGCMWrapper() = delete;
    
    static constexpr int IV_SIZE = 12;  // Recommended size for GCM IV
    static constexpr int TAG_SIZE = 16; // Recommended size for GCM Tag
};

#endif // AESGCM_WRAPPER_H
