#include "RSAWrapper.h"
#include <openssl/err.h>
#include <openssl/evp.h>

RSAWrapper::RSAWrapper(const string& public_key_path, const string& private_key_path)
    : public_key_path_(public_key_path), private_key_path_(private_key_path) {}

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


void RSAWrapper::sealEnvelope(const vector<unsigned char>& plaintext, vector<unsigned char>& ciphertext,
                              vector<unsigned char>& encrypted_key, vector<unsigned char>& iv,
                              vector<unsigned char>& tag) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> evp_pub_key(load_key(KeyType::Public), EVP_PKEY_free);

    // Resize buffers
    encrypted_key.resize(EVP_PKEY_size(evp_pub_key.get()));
    iv.resize(12); // 12 bytes is the recommended size for GCM
    tag.resize(16); // 16 bytes for the GCM tag

    // Generate a random IV
    if (1 != RAND_bytes(iv.data(), iv.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to generate IV.");
    }

    // Initialize encryption context with AES-GCM
    int encrypted_key_len = encrypted_key.size();
    unsigned char* ek = encrypted_key.data(); // Pointer to the key buffer
    EVP_PKEY* pub_key = evp_pub_key.get(); // Raw pointer to pass to EVP_SealInit
    if (1 != EVP_SealInit(ctx, EVP_aes_128_gcm(), &ek, &encrypted_key_len,
                          iv.data(), &pub_key, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("SealInit failed.");
    }

    // Encrypt the plaintext
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int len = 0, ciphertext_len = 0;
    const unsigned char* input_data = plaintext.data();
    size_t remaining = plaintext.size();

    while (remaining > 0) {
        int chunk_size = std::min(remaining, static_cast<size_t>(INT_MAX)); // Process in chunks of max size INT_MAX
        if (1 != EVP_SealUpdate(ctx, ciphertext.data() + ciphertext_len, &len, input_data, chunk_size)) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("SealUpdate failed.");
        }
        ciphertext_len += len;
        input_data += chunk_size;
        remaining -= chunk_size;
    }

    // Finalize encryption
    if (1 != EVP_SealFinal(ctx, ciphertext.data() + ciphertext_len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("SealFinal failed.");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Get the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get GCM tag.");
    }

    EVP_CIPHER_CTX_free(ctx);
}

vector<unsigned char> RSAWrapper::openEnvelope(const vector<unsigned char>& ciphertext, 
                                               const vector<unsigned char>& encrypted_key, 
                                               const vector<unsigned char>& iv,
                                               const vector<unsigned char>& tag) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> evp_priv_key(load_key(KeyType::Private), EVP_PKEY_free);

    // Initialize decryption context with AES-GCM
    if (1 != EVP_OpenInit(ctx, EVP_aes_128_gcm(), encrypted_key.data(), encrypted_key.size(),
                          iv.data(), evp_priv_key.get())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("OpenInit failed.");
    }

    // Provide the tag to verify integrity
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set GCM tag.");
    }

    // Decrypt the ciphertext
    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;
    const unsigned char* input_data = ciphertext.data();
    size_t remaining = ciphertext.size();

    while (remaining > 0) {
        int chunk_size = std::min(remaining, static_cast<size_t>(INT_MAX)); // Process in chunks of max size INT_MAX
        if (1 != EVP_OpenUpdate(ctx, plaintext.data() + plaintext_len, &len, input_data, chunk_size)) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("OpenUpdate failed.");
        }
        plaintext_len += len;
        input_data += chunk_size;
        remaining -= chunk_size;
    }

    // Finalize decryption
    if (1 != EVP_OpenFinal(ctx, plaintext.data() + plaintext_len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("OpenFinal failed: Data may have been tampered with.");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
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
    } else {
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
