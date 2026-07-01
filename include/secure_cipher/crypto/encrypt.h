#ifndef SECURE_CIPHER_CRYPTO_ENCRYPT_H
#define SECURE_CIPHER_CRYPTO_ENCRYPT_H

#include "secure_cipher/context.h"

#ifdef __cplusplus
extern "C" {
#endif

int encrypt_file(const AppContext *ctx, const char *input_path, int remove_plaintext);
int encrypt_directory(const AppContext *ctx, const char *dir_path);
int write_recovery_instructions(const char *dir_path, const char *keydir);

#ifdef __cplusplus
}
#endif

#endif
