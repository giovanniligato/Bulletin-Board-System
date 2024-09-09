#include "AESGCMWrapper.h"
#include <openssl/err.h>


void AESGCMWrapper::encrypt(const vector<unsigned char>& key, 
                            const vector<unsigned char>& plaintext, 
                            vector<unsigned char>& ciphertext,
                            vector<unsigned char>& iv,
                            vector<unsigned char>& tag,
                            const vector<unsigned char>& aad) {
    if (key.size() != 16) { // 128-bit key size
        throw runtime_error("Invalid key size. AES-128-GCM requires a 128-bit key.");
    }

    // Allocate and generate IV
    iv.resize(IV_SIZE);
    if (1 != RAND_bytes(iv.data(), IV_SIZE)) {
        throw runtime_error("Failed to generate IV.");
    }

    // Allocate tag
    tag.resize(TAG_SIZE);

    // Initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption operation.");
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set IV length.");
    }

    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize key and IV.");
    }

    int len = 0;
    ciphertext.resize(plaintext.size());

    // Provide AAD data if present
    if (!aad.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to process AAD.");
        }
    }

    // Encrypt the plaintext
    const unsigned char* input_ptr = plaintext.data();
    size_t remaining = plaintext.size();
    int ciphertext_len = 0;

    while (remaining > 0) {
        int chunk_size = min(remaining, static_cast<size_t>(INT_MAX));
        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data() + ciphertext_len, &len, input_ptr, chunk_size)) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to encrypt plaintext.");
        }
        ciphertext_len += len;
        input_ptr += chunk_size;
        remaining -= chunk_size;
    }

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to finalize encryption.");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get tag.");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

vector<unsigned char> AESGCMWrapper::decrypt(const vector<unsigned char>& key, 
                                             const vector<unsigned char>& ciphertext,
                                             const vector<unsigned char>& iv,
                                             const vector<unsigned char>& tag,
                                             const vector<unsigned char>& aad) {
    if (key.size() != 16) { // 128-bit key size
        throw runtime_error("Invalid key size. AES-128-GCM requires a 128-bit key.");
    }

    // Initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption operation.");
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set IV length.");
    }

    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize key and IV.");
    }

    int len = 0;
    vector<unsigned char> plaintext(ciphertext.size());

    // Provide AAD data if present
    if (!aad.empty()) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to process AAD.");
        }
    }

    // Decrypt the ciphertext
    const unsigned char* input_ptr = ciphertext.data();
    size_t remaining = ciphertext.size();
    int plaintext_len = 0;

    while (remaining > 0) {
        int chunk_size = min(remaining, static_cast<size_t>(INT_MAX));
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data() + plaintext_len, &len, input_ptr, chunk_size)) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to decrypt ciphertext.");
        }
        plaintext_len += len;
        input_ptr += chunk_size;
        remaining -= chunk_size;
    }

    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, const_cast<unsigned char*>(tag.data()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set tag.");
    }

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed: Data may have been tampered with.");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
