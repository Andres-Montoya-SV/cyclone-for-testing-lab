#ifndef SECURE_CIPHER_CRYPTO_KDF_H
#define SECURE_CIPHER_CRYPTO_KDF_H

#include "secure_cipher/context.h"
#include "secure_cipher/types.h"

#ifdef __cplusplus
extern "C" {
#endif

void kdf_default_pwhash_limits(unsigned char opslimit_out[4], unsigned char memlimit_out[4]);
size_t kdf_build_header_aad(unsigned char aad[32], const FileHeader *header);
int kdf_derive_file_key(
    const AppContext *ctx,
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const FileHeader *header
);
int kdf_classify_key_material(const char *material, size_t material_len);

#ifdef __cplusplus
}
#endif

#endif
