#ifndef SECURE_CIPHER_CRYPTO_KEYSTORE_H
#define SECURE_CIPHER_CRYPTO_KEYSTORE_H

#include "secure_cipher/context.h"

#ifdef __cplusplus
extern "C" {
#endif

int keystore_load_passphrase(AppContext *ctx, const char *keydir);
int keystore_init_keydir(const char *keydir);

#ifdef __cplusplus
}
#endif

#endif
