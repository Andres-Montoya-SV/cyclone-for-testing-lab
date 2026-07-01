#ifndef SECURE_CIPHER_CRYPTO_STREAM_IO_H
#define SECURE_CIPHER_CRYPTO_STREAM_IO_H

#include <stdio.h>

#include "secure_cipher/context.h"
#include "secure_cipher/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StreamBuffers {
    unsigned char *input;
    unsigned char *output;
    unsigned char *file_buf;
    size_t chunk_size;
} StreamBuffers;

size_t stream_io_chunk_size_for_path(const char *path);
int stream_io_alloc_buffers(size_t chunk_size, StreamBuffers *buffers);
void stream_io_free_buffers(StreamBuffers *buffers);
void stream_io_tune_file(FILE *file, unsigned char *buffer, size_t buffer_size);

int stream_io_encrypt_payload(
    const AppContext *ctx,
    const char *input_path,
    FILE *in,
    FILE *out,
    FileHeader *header,
    const unsigned char *aad,
    size_t aad_len
);

int stream_io_decrypt_payload(
    const AppContext *ctx,
    FILE *in,
    FILE *out,
    const FileHeader *header,
    const unsigned char *aad,
    size_t aad_len
);

#ifdef __cplusplus
}
#endif

#endif
