#include "RSAWrapper.h"

#include <openssl/err.h>
#include <openssl/evp.h>

RSAWrapper::RSAWrapper(const string& public_key_path, const string& private_key_path)
    : public_key_path_(public_key_path), private_key_path_(private_key_path) {

}

vector<unsigned char> RSAWrapper::encrypt(const vector<unsigned char>& data, KeyType key_type) const {
    unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> evp_key(load_key(key_type), EVP_PKEY_free);
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(evp_key.get(), nullptr);
    if (!pctx) {
        throw runtime_error("Failed to create EVP_PKEY_CTX.");
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("EVP_PKEY_encrypt_init failed.");
    }

    // Determine the required buffer length
    size_t outlen;
    if (EVP_PKEY_encrypt(pctx, nullptr, &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("Failed to determine encrypted buffer length: " + string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Allocate buffer with the required size
    vector<unsigned char> encrypted(outlen);

    // Perform the encryption
    if (EVP_PKEY_encrypt(pctx, encrypted.data(), &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("Encryption failed: " + string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Resize the encrypted buffer to the actual length
    encrypted.resize(outlen);

    EVP_PKEY_CTX_free(pctx);
    return encrypted;
}


vector<unsigned char> RSAWrapper::decrypt(const vector<unsigned char>& encrypted_data, KeyType key_type) const {
    unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> evp_key(load_key(key_type), EVP_PKEY_free);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(evp_key.get(), nullptr);
    if (!pctx) {
        throw runtime_error("Failed to create EVP_PKEY_CTX.");
    }

    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("EVP_PKEY_decrypt_init failed.");
    }

    // Determine the required buffer length
    size_t outlen;
    if (EVP_PKEY_decrypt(pctx, nullptr, &outlen, encrypted_data.data(), encrypted_data.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("Failed to determine decrypted buffer length: " + string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Allocate buffer with the required size
    vector<unsigned char> decrypted(outlen);

    // Perform the decryption
    if (EVP_PKEY_decrypt(pctx, decrypted.data(), &outlen, encrypted_data.data(), encrypted_data.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("Decryption failed: " + string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Resize the decrypted buffer to the actual length
    decrypted.resize(outlen);

    EVP_PKEY_CTX_free(pctx);
    return decrypted;
}

EVP_PKEY* RSAWrapper::load_key(KeyType key_type) const {
    FILE* key_file = nullptr;
    EVP_PKEY* evp_key = nullptr;

    if (key_type == KeyType::Public) {
        key_file = fopen(public_key_path_.c_str(), "r");
        if (!key_file) {
            throw runtime_error("Could not open public key file.");
        }
        evp_key = PEM_read_PUBKEY(key_file, nullptr, nullptr, nullptr);
    } 
    else {
        key_file = fopen(private_key_path_.c_str(), "r");
        if (!key_file) {
            throw runtime_error("Could not open private key file.");
        }
        evp_key = PEM_read_PrivateKey(key_file, nullptr, nullptr, (void*)"serverBBS");
    }
    fclose(key_file);

    if (!evp_key) {
        throw runtime_error("Could not read key.");
    }
    return evp_key;
}
