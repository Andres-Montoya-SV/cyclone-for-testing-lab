#ifndef SECURE_CIPHER_CRYPTO_WORK_POOL_H
#define SECURE_CIPHER_CRYPTO_WORK_POOL_H

#include "secure_cipher/context.h"

#ifdef __cplusplus
extern "C" {
#endif

int work_pool_encrypt_directory(const AppContext *ctx, const char *dir_path);
int work_pool_decrypt_directory(const AppContext *ctx, const char *dir_path);

#ifdef __cplusplus
}
#endif

#endif
