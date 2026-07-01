#include "secure_cipher/crypto/kdf.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static uint32_t read_le32(const unsigned char bytes[4]) {
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}

static void write_le32(unsigned char bytes[4], uint32_t value) {
    bytes[0] = (unsigned char) (value & 0xffU);
    bytes[1] = (unsigned char) ((value >> 8) & 0xffU);
    bytes[2] = (unsigned char) ((value >> 16) & 0xffU);
    bytes[3] = (unsigned char) ((value >> 24) & 0xffU);
}

void kdf_default_pwhash_limits(unsigned char opslimit_out[4], unsigned char memlimit_out[4]) {
    const char *profile = getenv(PWHASH_ENV);
    uint32_t opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    uint32_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    if (profile != NULL) {
        if (strcmp(profile, "interactive") == 0) {
            opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
            memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
        } else if (strcmp(profile, "sensitive") == 0) {
            opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
            memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;
        }
    }

    write_le32(opslimit_out, opslimit);
    write_le32(memlimit_out, memlimit);
}

int kdf_classify_key_material(const char *material, size_t material_len) {
    unsigned char probe[KEYGEN_RANDOM_BYTES];

    if (material_len == KEYGEN_RANDOM_BYTES * 2 &&
        sodium_hex2bin(probe, sizeof(probe), material, material_len, NULL, NULL, NULL) == 0) {
        sodium_memzero(probe, sizeof(probe));
        return KDF_MACHINE_BLOB;
    }

    sodium_memzero(probe, sizeof(probe));
    return KDF_ARGON2ID;
}

static int expand_domain_key(
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const unsigned char *master_key,
    size_t master_key_len
) {
    return crypto_generichash(
        key,
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
        master_key,
        master_key_len,
        (const unsigned char *) DOMAIN_SEPARATOR,
        sizeof(DOMAIN_SEPARATOR) - 1
    ) == 0;
}

static int derive_legacy_generichash_key(
    const AppContext *ctx,
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const unsigned char *salt,
    size_t salt_len
) {
    return crypto_generichash(
        key,
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
        (const unsigned char *) ctx->passphrase,
        ctx->passphrase_len,
        salt,
        salt_len
    ) == 0;
}

static int derive_argon2id_key(
    const AppContext *ctx,
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const unsigned char salt[FILE_SALT_BYTES],
    uint32_t opslimit,
    uint32_t memlimit
) {
    unsigned char master[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    int result;

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN || memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        fprintf(stderr, "Stored Argon2 parameters are below libsodium minimums.\n");
        return 0;
    }

    result = crypto_pwhash(
        master,
        sizeof(master),
        ctx->passphrase,
        ctx->passphrase_len,
        salt,
        opslimit,
        memlimit,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (result != 0) {
        if (result == -1 && errno == ENOMEM) {
            fprintf(stderr, "Argon2id key derivation needs more memory.\n");
        } else {
            fprintf(stderr, "Argon2id key derivation failed.\n");
        }
        return 0;
    }

    if (!expand_domain_key(key, master, sizeof(master))) {
        sodium_memzero(master, sizeof(master));
        return 0;
    }

    sodium_memzero(master, sizeof(master));
    return 1;
}

static int derive_machine_blob_key(
    const AppContext *ctx,
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const unsigned char *salt
) {
    unsigned char raw[KEYGEN_RANDOM_BYTES];
    unsigned char master[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (ctx->passphrase_len != sizeof(raw) * 2 ||
        sodium_hex2bin(raw, sizeof(raw), ctx->passphrase, ctx->passphrase_len, NULL, NULL, NULL) != 0) {
        return 0;
    }

    if (crypto_generichash(master, sizeof(master), raw, sizeof(raw), salt, FILE_SALT_BYTES) != 0) {
        sodium_memzero(raw, sizeof(raw));
        return 0;
    }

    sodium_memzero(raw, sizeof(raw));

    if (!expand_domain_key(key, master, sizeof(master))) {
        sodium_memzero(master, sizeof(master));
        return 0;
    }

    sodium_memzero(master, sizeof(master));
    return 1;
}

int kdf_derive_file_key(
    const AppContext *ctx,
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
    const FileHeader *header
) {
    if (ctx == NULL || ctx->passphrase == NULL || ctx->passphrase_len == 0) {
        return 0;
    }

    switch (header->kdf_id) {
    case KDF_LEGACY:
        return derive_legacy_generichash_key(ctx, key, NULL, 0);

    case KDF_GENERICHASH:
        return derive_legacy_generichash_key(ctx, key, header->salt, sizeof(header->salt));

    case KDF_ARGON2ID:
        return derive_argon2id_key(
            ctx,
            key,
            header->salt,
            read_le32(header->pwhash_opslimit),
            read_le32(header->pwhash_memlimit)
        );

    case KDF_MACHINE_BLOB:
        return derive_machine_blob_key(ctx, key, header->salt);

    default:
        fprintf(stderr, "Unsupported KDF id %u in file header.\n", header->kdf_id);
        return 0;
    }
}

size_t kdf_build_header_aad(unsigned char aad[32], const FileHeader *header) {
    size_t aad_len = 2 + FILE_SALT_BYTES;

    aad[0] = header->version;
    aad[1] = header->kdf_id;
    memcpy(aad + 2, header->salt, FILE_SALT_BYTES);

    if (header->version >= HEADER_VERSION_CURRENT) {
        memcpy(aad + aad_len, header->pwhash_opslimit, 4);
        aad_len += 4;
        memcpy(aad + aad_len, header->pwhash_memlimit, 4);
        aad_len += 4;
    }

    return aad_len;
}
