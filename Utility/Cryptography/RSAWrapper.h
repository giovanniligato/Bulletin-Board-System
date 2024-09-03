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

class RSAWrapper {
public:
    RSAWrapper(const string& public_key_path, const string& private_key_path);
    
    // Encrypt data using the public key
    vector<unsigned char> encrypt(const string& data) const;

    // Decrypt data using the private key
    string decrypt(const vector<unsigned char>& encrypted_data) const;
    
    // Encrypt a message using a digital envelope with AES-GCM
    void sealEnvelope(const string& plaintext, vector<unsigned char>& ciphertext,
                      vector<unsigned char>& encrypted_key, vector<unsigned char>& iv,
                      vector<unsigned char>& tag) const;
    
    // Decrypt a message using a digital envelope with AES-GCM
    string openEnvelope(const vector<unsigned char>& ciphertext, 
                        const vector<unsigned char>& encrypted_key, 
                        const vector<unsigned char>& iv,
                        const vector<unsigned char>& tag) const;
    
private:
    EVP_PKEY* load_public_key() const;
    EVP_PKEY* load_private_key() const;

    string public_key_path_;
    string private_key_path_;
};

#endif // RSAWRAPPER_H
