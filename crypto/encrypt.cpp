#include "secure_cipher/crypto/encrypt.h"

#include "secure_cipher/config.h"
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

static std::mutex g_encrypt_log_mutex;

static void encrypt_log_printf(const char *format, ...) {
    std::lock_guard<std::mutex> lock(g_encrypt_log_mutex);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static void encrypt_log_fprintf(FILE *stream, const char *format, ...) {
    std::lock_guard<std::mutex> lock(g_encrypt_log_mutex);
    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);
    va_end(args);
}

static int encrypt_file_cb(const AppContext *ctx, const char *input_path, int remove_plaintext);

int encrypt_directory(const AppContext *ctx, const char *dir_path) {
    return work_pool_encrypt_directory(ctx, dir_path);
}

static int encrypt_file_cb(const AppContext *ctx, const char *input_path, int remove_plaintext) {
    char *output_path = path_encrypted_output(input_path);
    if (output_path == NULL) {
        encrypt_log_fprintf(stderr, "Could not allocate output path.\n");
        return 0;
    }

    if (path_output_exists(output_path)) {
        free(output_path);
        return 0;
    }

    if (ctx->dry_run) {
        encrypt_log_printf("[dry-run] would encrypt '%s' -> '%s'", input_path, output_path);
        if (remove_plaintext) {
            encrypt_log_printf(" and remove plaintext");
        }
        encrypt_log_printf("\n");
        free(output_path);
        return 1;
    }

    FILE *in = fopen(input_path, "rb");
    if (in == NULL) {
        encrypt_log_fprintf(
            stderr,
            "Could not open input file '%s': %s\n",
            input_path,
            strerror(errno)
        );
        free(output_path);
        return 0;
    }

    FILE *out = fopen(output_path, "wb");
    if (out == NULL) {
        encrypt_log_fprintf(
            stderr,
            "Could not create output file '%s': %s\n",
            output_path,
            strerror(errno)
        );
        fclose(in);
        free(output_path);
        return 0;
    }

    FileHeader header;
    header_prepare_encrypt(&header, ctx);

    unsigned char aad[32];
    const size_t aad_len = kdf_build_header_aad(aad, &header);

    if (!stream_io_encrypt_payload(ctx, input_path, in, out, &header, aad, aad_len)) {
        encrypt_log_fprintf(stderr, "Encryption failed for '%s'.\n", input_path);
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

    encrypt_log_printf("File encrypted safely: %s -> %s\n", input_path, output_path);

    if (remove_plaintext) {
        if (remove(input_path) != 0) {
            encrypt_log_fprintf(
                stderr,
                "Warning: could not remove plaintext '%s': %s (encrypted copy exists at '%s').\n",
                input_path,
                strerror(errno),
                output_path
            );
            free(output_path);
            return 0;
        }

        encrypt_log_printf("Plaintext removed: %s\n", input_path);
    }

    free(output_path);
    return 1;
}

int encrypt_file(const AppContext *ctx, const char *input_path, int remove_plaintext) {
    return encrypt_file_cb(ctx, input_path, remove_plaintext);
}

int write_recovery_instructions(const char *dir_path, const char *keydir) {
    size_t dir_len = strlen(dir_path);
    size_t needs_slash = (dir_len > 0 && dir_path[dir_len - 1] != '/') ? 1 : 0;
    size_t path_size = dir_len + needs_slash + strlen(RECOVERY_FILENAME) + 1;
    char *instructions_path = (char *) malloc(path_size);

    if (instructions_path == NULL) {
        fprintf(stderr, "Out of memory.\n");
        return 0;
    }

    if (snprintf(
            instructions_path,
            path_size,
            needs_slash ? "%s/%s" : "%s%s",
            dir_path,
            RECOVERY_FILENAME
        ) >= (int) path_size) {
        free(instructions_path);
        return 0;
    }

    FILE *f = fopen(instructions_path, "w");
    if (f == NULL) {
        fprintf(stderr, "Could not create instructions file '%s': %s\n", instructions_path, strerror(errno));
        free(instructions_path);
        return 0;
    }

    fprintf(f,
        "========================================================================\n"
        "                     CYBERSECURITY SIMULATION NOTICE                    \n"
        "========================================================================\n"
        "This directory has been locked as part of an authorized file-locking\n"
        "simulation. Your files are encrypted using XChaCha20-Poly1305.\n"
        "\n"
        "--- HOW TO DECRYPT AND RESTORE YOUR FILES ---\n"
        "To recover the files, execute the following command in your terminal:\n"
        "\n"
        "  ./secure_cipher ");

    if (keydir != NULL) {
        fprintf(f, "-k %s ", keydir);
    } else {
        fprintf(f, "-k <keydir> ");
    }

    fprintf(f, "decrypt %s\n\n", dir_path);

    fprintf(f,
        "--- EDUCATIONAL SIMULATION NOTES ---\n"
        "1. Encryption uses libsodium secretstream (XChaCha20-Poly1305).\n"
        "2. Look for IOCs: .enc files, Argon2 CPU use, key directory access.\n"
        "3. Defense: offline backups, EDR, least privilege.\n"
        "========================================================================\n"
    );

    fclose(f);
    printf("Recovery instructions deposited at: %s\n", instructions_path);
    free(instructions_path);
    return 1;
}
