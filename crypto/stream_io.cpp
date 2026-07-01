#include "secure_cipher/crypto/stream_io.h"

#include "secure_cipher/crypto/kdf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sodium.h>

#if defined(__linux__)
#include <fcntl.h>
#endif

static void stream_io_advise_sequential(FILE *file) {
#if defined(__linux__)
    const int fd = fileno(file);
    if (fd >= 0) {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }
#else
    (void) file;
#endif
}

size_t stream_io_io_buffer_size_for_path(const char *path) {
    struct stat st;

    if (path == NULL || stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return CHUNK_SIZE * 16;
    }

    if (st.st_size >= LARGE_FILE_THRESHOLD) {
        return FILE_IO_BUFFER_SIZE;
    }

    if (st.st_size >= CHUNK_SIZE * 64) {
        return CHUNK_SIZE * 64;
    }

    return CHUNK_SIZE * 16;
}

size_t stream_io_chunk_size_for_path(const char *path) {
    (void) path;
    return CHUNK_SIZE;
}

int stream_io_alloc_buffers(size_t chunk_size, StreamBuffers *buffers) {
    size_t output_size;

    if (buffers == NULL || chunk_size == 0) {
        return 0;
    }

    output_size = chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES;
    buffers->chunk_size = chunk_size;
    buffers->input = (unsigned char *) sodium_malloc(chunk_size);
    buffers->output = (unsigned char *) sodium_malloc(output_size);
    buffers->file_buf = (unsigned char *) sodium_malloc(FILE_IO_BUFFER_SIZE);

    if (buffers->input == NULL || buffers->output == NULL) {
        stream_io_free_buffers(buffers);
        return 0;
    }

    return 1;
}

void stream_io_free_buffers(StreamBuffers *buffers) {
    if (buffers == NULL) {
        return;
    }

    if (buffers->input != NULL) {
        sodium_memzero(buffers->input, buffers->chunk_size);
        sodium_free(buffers->input);
        buffers->input = NULL;
    }

    if (buffers->output != NULL) {
        sodium_free(buffers->output);
        buffers->output = NULL;
    }

    if (buffers->file_buf != NULL) {
        sodium_free(buffers->file_buf);
        buffers->file_buf = NULL;
    }

    buffers->chunk_size = 0;
}

static void stream_io_release_file_buffer(FILE *file, unsigned char *buffer) {
    if (file != NULL) {
        fflush(file);
        setvbuf(file, NULL, _IONBF, 0);
    }

    if (buffer != NULL) {
        sodium_free(buffer);
    }
}

void stream_io_tune_file(FILE *file, unsigned char *buffer, size_t buffer_size) {
    if (file == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    setvbuf(file, (char *) buffer, _IOFBF, buffer_size);
    stream_io_advise_sequential(file);
}

static void stream_io_cleanup_files(
    FILE *in,
    FILE *out,
    StreamBuffers *buffers,
    unsigned char *out_file_buf
) {
    if (buffers != NULL) {
        stream_io_release_file_buffer(in, buffers->file_buf);
        buffers->file_buf = NULL;
        stream_io_free_buffers(buffers);
    }

    stream_io_release_file_buffer(out, out_file_buf);
}

int stream_io_encrypt_payload(
    const AppContext *ctx,
    const char *input_path,
    FILE *in,
    FILE *out,
    FileHeader *header,
    const unsigned char *aad,
    size_t aad_len
) {
    StreamBuffers buffers;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    int eof = 0;
    unsigned char *out_file_buf = NULL;
    int ok = 0;

    (void) ctx;

    memset(&buffers, 0, sizeof(buffers));

    if (!stream_io_alloc_buffers(stream_io_chunk_size_for_path(input_path), &buffers)) {
        return 0;
    }

    const size_t io_buffer_size = stream_io_io_buffer_size_for_path(input_path);
    stream_io_tune_file(in, buffers.file_buf, io_buffer_size);

    out_file_buf = (unsigned char *) sodium_malloc(io_buffer_size);
    if (out_file_buf != NULL) {
        stream_io_tune_file(out, out_file_buf, io_buffer_size);
    }

    if (!kdf_derive_file_key(ctx, key, header)) {
        goto cleanup;
    }

    crypto_secretstream_xchacha20poly1305_init_push(&state, header->stream_header, key);

    if (fwrite(header, sizeof(*header), 1, out) != 1) {
        goto cleanup;
    }

    do {
        const size_t read_count = fread(buffers.input, 1, buffers.chunk_size, in);

        if (ferror(in)) {
            goto cleanup;
        }

        eof = feof(in);
        const unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long encrypted_len;

        crypto_secretstream_xchacha20poly1305_push(
            &state,
            buffers.output,
            &encrypted_len,
            buffers.input,
            read_count,
            aad,
            aad_len,
            tag
        );

        if (fwrite(buffers.output, 1, encrypted_len, out) != encrypted_len) {
            goto cleanup;
        }
    } while (!eof);

    ok = 1;

cleanup:
    sodium_memzero(key, sizeof(key));
    stream_io_cleanup_files(in, out, &buffers, out_file_buf);
    return ok;
}

int stream_io_decrypt_payload(
    const AppContext *ctx,
    FILE *in,
    FILE *out,
    const FileHeader *header,
    const unsigned char *aad,
    size_t aad_len
) {
    const size_t read_buffer_size = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
    StreamBuffers buffers;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char tag = 0;
    size_t read_count;
    unsigned char *out_file_buf = NULL;
    const size_t io_buffer_size = FILE_IO_BUFFER_SIZE;
    int ok = 0;

    (void) ctx;

    memset(&buffers, 0, sizeof(buffers));

    if (!stream_io_alloc_buffers(read_buffer_size, &buffers)) {
        return 0;
    }

    stream_io_tune_file(in, buffers.file_buf, io_buffer_size);

    out_file_buf = (unsigned char *) sodium_malloc(io_buffer_size);
    if (out_file_buf != NULL) {
        stream_io_tune_file(out, out_file_buf, io_buffer_size);
    }

    if (!kdf_derive_file_key(ctx, key, header)) {
        goto cleanup;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header->stream_header, key) != 0) {
        goto cleanup;
    }

    while ((read_count = fread(buffers.input, 1, buffers.chunk_size, in)) > 0) {
        unsigned long long decrypted_len;
        const int result = crypto_secretstream_xchacha20poly1305_pull(
            &state,
            buffers.output,
            &decrypted_len,
            &tag,
            buffers.input,
            read_count,
            aad,
            aad_len
        );

        if (result != 0) {
            goto cleanup;
        }

        if (fwrite(buffers.output, 1, decrypted_len, out) != decrypted_len) {
            goto cleanup;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }

    if (ferror(in) || tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    sodium_memzero(key, sizeof(key));
    stream_io_cleanup_files(in, out, &buffers, out_file_buf);
    return ok;
}
