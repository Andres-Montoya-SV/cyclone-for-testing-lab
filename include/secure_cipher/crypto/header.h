#ifndef SECURE_CIPHER_CRYPTO_HEADER_H
#define SECURE_CIPHER_CRYPTO_HEADER_H

#include <stdio.h>

#include "secure_cipher/context.h"
#include "secure_cipher/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int header_read(FILE *in, FileHeader *header, FileHeaderLegacy *legacy_header, int *is_legacy);
void header_prepare_encrypt(FileHeader *header, const AppContext *ctx);

#ifdef __cplusplus
}
#endif

#endif
