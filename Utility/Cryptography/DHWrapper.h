#ifndef DH_WRAPPER_H
#define DH_WRAPPER_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>

using namespace std;

class DHWrapper {
public:
    DHWrapper(int keyLength);
    ~DHWrapper();

    vector<unsigned char> getPublicKey();
    void loadPeerPublicKey(const vector<unsigned char>& peerPublicKey);
    vector<unsigned char> computeSharedSecret();

private:
    EVP_PKEY* pkey;
    EVP_PKEY* peerKey;
    int keyLength;

    vector<unsigned char> keyToBytes(EVP_PKEY* key, bool isPublic);
    EVP_PKEY* bytesToKey(const vector<unsigned char>& keyBytes, bool isPublic);
    EVP_PKEY* generateDHKeyPair(int keyLength);
};

#endif // DH_WRAPPER_H
