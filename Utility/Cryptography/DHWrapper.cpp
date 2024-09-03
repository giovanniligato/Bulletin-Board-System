#include "DHWrapper.h"

// Constructor: Generate or load Diffie-Hellman parameters and keys
DHWrapper::DHWrapper(int keyLength) : pkey(nullptr), peerKey(nullptr), keyLength(keyLength) {
    pkey = GenerateDHKeyPair(keyLength);
}

// Destructor: Clean up resources
DHWrapper::~DHWrapper() {
    if (pkey) EVP_PKEY_free(pkey);
    if (peerKey) EVP_PKEY_free(peerKey);
}

// Get the public key in PEM format
string DHWrapper::GetPublicKey() {
    return KeyToString(pkey, true);
}

// Load a peer's public key from a PEM string
void DHWrapper::LoadPeerPublicKey(const string& peerPublicKey) {
    if (peerKey) EVP_PKEY_free(peerKey);
    peerKey = StringToKey(peerPublicKey, true);
}

// Compute the shared secret
string DHWrapper::ComputeSharedSecret() {
    if (!peerKey) {
        throw runtime_error("Peer public key not loaded");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        throw runtime_error("Error creating EVP_PKEY_CTX");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error initializing key derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error setting peer public key");
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error determining shared secret length");
    }

    vector<unsigned char> secret(secretLen);
    if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error deriving shared secret");
    }

    EVP_PKEY_CTX_free(ctx);
    return string(secret.begin(), secret.end());
}

// Helper function: Convert EVP_PKEY to PEM string
string DHWrapper::KeyToString(EVP_PKEY* key, bool isPublic) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (isPublic) {
        PEM_write_bio_PUBKEY(bio, key);
    } else {
        PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    }

    BUF_MEM* memPtr;
    BIO_get_mem_ptr(bio, &memPtr);

    string keyStr(memPtr->data, memPtr->length);
    BIO_free(bio);

    return keyStr;
}

// Helper function: Convert PEM string to EVP_PKEY
EVP_PKEY* DHWrapper::StringToKey(const string& keyStr, bool isPublic) {
    BIO* bio = BIO_new_mem_buf(keyStr.data(), keyStr.size());
    EVP_PKEY* key = nullptr;

    if (isPublic) {
        key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    } else {
        key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    }

    BIO_free(bio);

    if (!key) {
        throw runtime_error("Error loading key");
    }

    return key;
}

// Helper function: Generate a DH key pair with the specified key length
EVP_PKEY* DHWrapper::GenerateDHKeyPair(int keyLength) {
    EVP_PKEY* dh_params = EVP_PKEY_new();
    
    if (!dh_params) {
        throw runtime_error("Error creating EVP_PKEY for DH parameters");
    }

    if (keyLength == 1024) {
        if (!EVP_PKEY_set1_DH(dh_params, DH_get_1024_160())) {
            EVP_PKEY_free(dh_params);
            throw runtime_error("Error setting 1024-bit DH parameters");
        }
    } else if (keyLength == 2048) {
        if (!EVP_PKEY_set1_DH(dh_params, DH_get_2048_224())) {
            EVP_PKEY_free(dh_params);
            throw runtime_error("Error setting 2048-bit DH parameters");
        }
    } else {
        EVP_PKEY_free(dh_params);
        throw invalid_argument("Unsupported key length. Use 1024 or 2048.");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
    if (!ctx) {
        EVP_PKEY_free(dh_params);
        throw runtime_error("Error creating EVP_PKEY_CTX for key generation");
    }

    EVP_PKEY* privkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        throw runtime_error("Error initializing key generation");
    }

    if (EVP_PKEY_keygen(ctx, &privkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        throw runtime_error("Error generating DH key pair");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    return privkey;
}

