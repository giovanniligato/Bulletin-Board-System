#ifndef UTILITY
#define UTILITY

#include <openssl/evp.h>


// Diffie-Hellman key exchange

// Parameters Generation
EVP_PKEY* dh_params;
dh_params = EVP_PKEY_new();
EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());

// Generation of private/public key pair
EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
EVP_PKEY* privkey = NULL;
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_keygen(ctx, &privkey);

// Extract public key for sending to peer
EVP_PKEY* pubkey = NULL;
// ...


// Peer public key
EVP_PKEY* peer_pubkey = NULL;
// ... receive peer_pubkey from peer

// Initializing shared secret derivation context
EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(privkey, NULL);
EVP_PKEY_derive_init(ctx_drv);
EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey);

unsigned char* secret;

// Retrieving shared secret's length
size_t secret_len;
EVP_PKEY_derive(ctx_drv, NULL, &secret_len);

// Deriving shared secret
secret = (unsigned char*)OPENSSL_malloc(secret_len);
EVP_PKEY_derive(ctx_drv, secret, &secret_len);

#endif