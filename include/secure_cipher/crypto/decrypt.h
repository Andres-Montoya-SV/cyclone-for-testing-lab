#ifndef SECURE_CIPHER_CRYPTO_DECRYPT_H
#define SECURE_CIPHER_CRYPTO_DECRYPT_H

#include "secure_cipher/context.h"

#ifdef __cplusplus
extern "C" {
#endif

int decrypt_file(const AppContext *ctx, const char *input_path, int remove_encrypted);
int decrypt_directory(const AppContext *ctx, const char *dir_path);

#ifdef __cplusplus
}
#endif

#endif
