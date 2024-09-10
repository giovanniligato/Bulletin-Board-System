#ifndef RSA_WRAPPER_H
#define RSA_WRAPPER_H

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

enum class KeyType {
    Public,
    Private
};

class RSAWrapper {
public:
    RSAWrapper(const string& public_key_path, const string& private_key_path);
    
    // Encrypt data using the specified key type
    vector<unsigned char> encrypt(const vector<unsigned char>& data, KeyType key_type) const;

    // Decrypt data using the specified key type
    vector<unsigned char> decrypt(const vector<unsigned char>& encrypted_data, KeyType key_type) const;
    
private:
    EVP_PKEY* load_key(KeyType key_type) const;

    string public_key_path_;
    string private_key_path_;
};

#endif // RSA_WRAPPER_H
