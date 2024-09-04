#ifndef RSAWRAPPER_H
#define RSAWRAPPER_H

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

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
    
    // Encrypt a message using a digital envelope with AES-GCM
    void sealEnvelope(const vector<unsigned char>& plaintext, vector<unsigned char>& ciphertext,
                      vector<unsigned char>& encrypted_key, vector<unsigned char>& iv,
                      vector<unsigned char>& tag) const;
    
    // Decrypt a message using a digital envelope with AES-GCM
    vector<unsigned char> openEnvelope(const vector<unsigned char>& ciphertext, 
                                       const vector<unsigned char>& encrypted_key, 
                                       const vector<unsigned char>& iv,
                                       const vector<unsigned char>& tag) const;
    
private:
    EVP_PKEY* load_key(KeyType key_type) const;

    string public_key_path_;
    string private_key_path_;
};

#endif // RSAWRAPPER_H
