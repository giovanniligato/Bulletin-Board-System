#include "DHWrapper.h"

#include <arpa/inet.h>
#include "AESGCMWrapper.h"
#include "RSAWrapper.h"
#include "Randomness.h"
#include "Hash.h"
#include "../../Packets/StartPacket.h"

// Constructor: Generate or load Diffie-Hellman parameters and keys
DHWrapper::DHWrapper(int keyLength) : pkey(nullptr), peerKey(nullptr), keyLength(keyLength) {
    pkey = generateDHKeyPair(keyLength);
}

// Destructor: Clean up resources
DHWrapper::~DHWrapper() {
    if (pkey) EVP_PKEY_free(pkey);
    if (peerKey) EVP_PKEY_free(peerKey);
}

// Get the public key in PEM format as a vector of unsigned char
vector<unsigned char> DHWrapper::getPublicKey() {
    return keyToBytes(pkey, true);
}

// Load a peer's public key from a PEM vector of unsigned char
void DHWrapper::loadPeerPublicKey(const vector<unsigned char>& peerPublicKey) {
    if (peerKey) EVP_PKEY_free(peerKey);
    peerKey = bytesToKey(peerPublicKey, true);
}

// Compute the shared secret
vector<unsigned char> DHWrapper::computeSharedSecret() {
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
    secret.resize(secretLen);

    return secret;
}

// Helper function: Convert EVP_PKEY to PEM bytes
vector<unsigned char> DHWrapper::keyToBytes(EVP_PKEY* key, bool isPublic) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (isPublic) {
        PEM_write_bio_PUBKEY(bio, key);
    } else {
        PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    }

    BUF_MEM* memPtr;
    BIO_get_mem_ptr(bio, &memPtr);

    vector<unsigned char> keyBytes(memPtr->data, memPtr->data + memPtr->length);
    BIO_free(bio);

    return keyBytes;
}

// Helper function: Convert PEM bytes to EVP_PKEY
EVP_PKEY* DHWrapper::bytesToKey(const vector<unsigned char>& keyBytes, bool isPublic) {
    BIO* bio = BIO_new_mem_buf(keyBytes.data(), keyBytes.size());
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
EVP_PKEY* DHWrapper::generateDHKeyPair(int keyLength) {
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


// Complete key exchange (client side)
vector<unsigned char> DHWrapper::clientKeyExchange(int socket, int sessionKeyLength) {

    if (sessionKeyLength > 32) {
        throw invalid_argument("Session key length must be at most 32 bytes.");
    }

    // Generate a random 16 byte ephemeral key, used for just for authentication purposes
    vector<unsigned char> authKey =  generateRandomBytes(16);

    // Encrypt the authentication key with the server's public key
    RSAWrapper rsaWrapper("Client/Storage/Keys/server_pubkey.pem", "");
    vector<unsigned char> encrypted_authKey = rsaWrapper.encrypt(authKey, KeyType::Public);

    // Send the encrypted authentication key to the server
    
    // 256 Bytes
    send(socket, encrypted_authKey.data(), encrypted_authKey.size(), 0);

    vector<unsigned char> DH_public_key = getPublicKey();

    // Generate a nonce to prevent replay attacks
    vector<unsigned char> nonce = generateRandomBytes(16);

    vector<unsigned char> aad;

    // Insert into the aad the DH_public_key and the nonce
    aad.insert(aad.end(), DH_public_key.begin(), DH_public_key.end());
    aad.insert(aad.end(), nonce.begin(), nonce.end());

    // Construct the StartPacket
    StartPacket startPacket(aad);

    // Securely send the StartPacket to the server
    startPacket.send(socket, authKey);

    // Receive the response from the server
    StartPacket receivedStartPacket = StartPacket::receive(socket, authKey);

    // Extract the server's public key and nonce from the AAD (last 16 bytes are the nonce)
    vector<unsigned char> server_DH_public_key(receivedStartPacket.getAAD().begin(), receivedStartPacket.getAAD().end() - 16);
    vector<unsigned char> received_nonce(receivedStartPacket.getAAD().end() - 16, receivedStartPacket.getAAD().end());

    // Check if the nonce is the same as the one sent
    if (nonce != received_nonce) {
        throw runtime_error("Nonce mismatch.");
    }

    // Load the server's public key
    loadPeerPublicKey(server_DH_public_key);

    // Compute the shared secret
    vector<unsigned char> DH_shared_secret = computeSharedSecret();

    // Before using the shared secret as the session key, it is a good practice to hash it
    vector<unsigned char> sessionKey = Hash::computeSHA256(DH_shared_secret);

    // Resize the session key to the desired length
    sessionKey.resize(sessionKeyLength);

    return sessionKey;
}

// Complete key exchange (server side)
vector<unsigned char> DHWrapper::serverKeyExchange(int socket, int sessionKeyLength) {

    if (sessionKeyLength > 32) {
        throw invalid_argument("Session key length must be at most 32 bytes.");
    }

    // Receive the encrypted authentication key from the client
        
    // 256 Bytes
    vector<unsigned char> encrypted_authKey(256);
    int res = recv(socket, encrypted_authKey.data(), encrypted_authKey.size(), 0);
    if (res <= 0) {
        if (res == 0) {
            throw runtime_error("Connection closed by peer");
        }
        throw runtime_error("Failed to receive encrypted authentication key");
    }

    // Decrypt the authentication key with the server's private key
    RSAWrapper rsaWrapper("", "Server/Storage/Keys/server_privkey.pem");
    vector<unsigned char> authKey = rsaWrapper.decrypt(encrypted_authKey, KeyType::Private);

    // Receive the StartPacket from the client
    StartPacket startPacket = StartPacket::receive(socket, authKey);

    // Extract the client's public key and nonce from the AAD (last 16 bytes are the nonce)
    vector<unsigned char> client_DH_public_key(startPacket.getAAD().begin(), startPacket.getAAD().end() - 16);
    vector<unsigned char> nonce(startPacket.getAAD().end() - 16, startPacket.getAAD().end());

    // Generate the server's public key
    vector<unsigned char> DH_public_key = getPublicKey();

    // Sending back to the client the server's public key and the nonce

    // Insert into the aad the DH_public_key and the nonce
    vector<unsigned char> aad;
    aad.insert(aad.end(), DH_public_key.begin(), DH_public_key.end());
    aad.insert(aad.end(), nonce.begin(), nonce.end());

    // Construct the StartPacket
    StartPacket responseStartPacket(aad);

    // Securely send the StartPacket to the client
    responseStartPacket.send(socket, authKey);

    // Load the client's public key
    loadPeerPublicKey(client_DH_public_key);

    // Compute the shared secret
    vector<unsigned char> DH_shared_secret = computeSharedSecret();
    // DH shared secret is 128 bytes long

    // Before using the shared secret as the session key, it is a good practice to hash it
    vector<unsigned char> sessionKey = Hash::computeSHA256(DH_shared_secret);
    // Session key is 32 bytes long

    // Resize the session key to the desired length
    sessionKey.resize(sessionKeyLength);

    return sessionKey;
}
