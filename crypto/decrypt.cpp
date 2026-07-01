#include "secure_cipher/config.h"
#include "secure_cipher/crypto/decrypt.h"

#include "secure_cipher/crypto/header.h"
#include "secure_cipher/crypto/kdf.h"
#include "secure_cipher/crypto/stream_io.h"
#include "secure_cipher/crypto/work_pool.h"
#include "secure_cipher/path.h"

#include <errno.h>
#include <mutex>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static std::mutex g_decrypt_log_mutex;

static void decrypt_log_printf(const char *format, ...) {
    std::lock_guard<std::mutex> lock(g_decrypt_log_mutex);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static void decrypt_log_fprintf(FILE *stream, const char *format, ...) {
    std::lock_guard<std::mutex> lock(g_decrypt_log_mutex);
    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);
    va_end(args);
}

static int decrypt_file_cb(const AppContext *ctx, const char *input_path, int remove_encrypted);

int decrypt_directory(const AppContext *ctx, const char *dir_path) {
    return work_pool_decrypt_directory(ctx, dir_path);
}

static int decrypt_file_cb(const AppContext *ctx, const char *input_path, int remove_encrypted) {
    char *output_path = path_decrypted_output(input_path);
    if (output_path == NULL) {
        decrypt_log_fprintf(stderr, "Could not allocate output path.\n");
        return 0;
    }

    if (path_output_exists(output_path)) {
        free(output_path);
        return 0;
    }

    if (ctx->dry_run) {
        decrypt_log_printf("[dry-run] would decrypt '%s' -> '%s'", input_path, output_path);
        if (remove_encrypted) {
            decrypt_log_printf(" and remove encrypted file");
        }
        decrypt_log_printf("\n");
        free(output_path);
        return 1;
    }

    FILE *in = fopen(input_path, "rb");
    if (in == NULL) {
        decrypt_log_fprintf(
            stderr,
            "Could not open encrypted file '%s': %s\n",
            input_path,
            strerror(errno)
        );
        free(output_path);
        return 0;
    }

    FileHeader header;
    FileHeaderLegacy legacy_header;
    int is_legacy = 0;
    if (!header_read(in, &header, &legacy_header, &is_legacy)) {
        decrypt_log_fprintf(stderr, "Could not read encrypted file header for '%s'.\n", input_path);
        fclose(in);
        free(output_path);
        return 0;
    }

    unsigned char aad[32];
    const size_t aad_len =
        (header.version >= HEADER_VERSION_CURRENT) ? kdf_build_header_aad(aad, &header) : 0;

    FILE *out = fopen(output_path, "wb");
    if (out == NULL) {
        decrypt_log_fprintf(
            stderr,
            "Could not create decrypted file '%s': %s\n",
            output_path,
            strerror(errno)
        );
        sodium_memzero(aad, sizeof(aad));
        fclose(in);
        free(output_path);
        return 0;
    }

    if (!stream_io_decrypt_payload(ctx, in, out, &header, aad, aad_len)) {
        decrypt_log_fprintf(
            stderr,
            "Decryption failed for '%s'. Check key and data integrity.\n",
            input_path
        );
        sodium_memzero(aad, sizeof(aad));
        fclose(in);
        fclose(out);
        remove(output_path);
        free(output_path);
        return 0;
    }

    sodium_memzero(aad, sizeof(aad));
    fclose(in);
    fclose(out);

    decrypt_log_printf("File decrypted safely: %s -> %s\n", input_path, output_path);

    if (remove_encrypted) {
        if (remove(input_path) != 0) {
            decrypt_log_fprintf(
                stderr,
                "Warning: could not remove encrypted file '%s': %s (decrypted copy is '%s').\n",
                input_path,
                strerror(errno),
                output_path
            );
            free(output_path);
            return 0;
        }

        decrypt_log_printf("Encrypted file removed: %s\n", input_path);
    }

    free(output_path);
    return 1;
}

int decrypt_file(const AppContext *ctx, const char *input_path, int remove_encrypted) {
    return decrypt_file_cb(ctx, input_path, remove_encrypted);
}
