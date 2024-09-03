#ifndef DH_WRAPPER_H
#define DH_WRAPPER_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <vector>
#include <stdexcept>

using namespace std;

class DHWrapper {
public:
    DHWrapper(int keyLength);
    ~DHWrapper();

    string GetPublicKey();
    void LoadPeerPublicKey(const string& peerPublicKey);
    string ComputeSharedSecret();

private:
    EVP_PKEY* pkey;
    EVP_PKEY* peerKey;
    int keyLength;

    string KeyToString(EVP_PKEY* key, bool isPublic);
    EVP_PKEY* StringToKey(const string& keyStr, bool isPublic);
    EVP_PKEY* GenerateDHKeyPair(int keyLength);
};


#endif