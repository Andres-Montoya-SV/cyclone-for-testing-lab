#include "secure_cipher/crypto/header.h"
#include "secure_cipher/crypto/kdf.h"

#include <string.h>

int header_read(FILE *in, FileHeader *header, FileHeaderLegacy *legacy_header, int *is_legacy) {
    if (fread(header->magic, SCIPHER_MAGIC_LEN, 1, in) != 1) {
        return 0;
    }

    if (sodium_memcmp(header->magic, SCIPHER_MAGIC, SCIPHER_MAGIC_LEN) != 0) {
        return 0;
    }

    if (fread(&header->version, 1, 1, in) != 1) {
        return 0;
    }

    if (header->version == HEADER_VERSION_CURRENT) {
        if (fread(&header->kdf_id, 1, 1, in) != 1) {
            return 0;
        }

        if (fread(header->salt, FILE_SALT_BYTES, 1, in) != 1) {
            return 0;
        }

        if (fread(header->pwhash_opslimit, 4, 1, in) != 1) {
            return 0;
        }

        if (fread(header->pwhash_memlimit, 4, 1, in) != 1) {
            return 0;
        }

        if (fread(header->stream_header, sizeof(header->stream_header), 1, in) != 1) {
            return 0;
        }

        *is_legacy = 0;
        return 1;
    }

    if (header->version == HEADER_VERSION_GENERICHASH) {
        header->kdf_id = KDF_GENERICHASH;
        sodium_memzero(header->pwhash_opslimit, sizeof(header->pwhash_opslimit));
        sodium_memzero(header->pwhash_memlimit, sizeof(header->pwhash_memlimit));

        if (fread(header->salt, FILE_SALT_BYTES, 1, in) != 1) {
            return 0;
        }

        if (fread(header->stream_header, sizeof(header->stream_header), 1, in) != 1) {
            return 0;
        }

        *is_legacy = 0;
        return 1;
    }

    if (fseek(in, -(long) (1 + SCIPHER_MAGIC_LEN), SEEK_CUR) != 0) {
        return 0;
    }

    if (fread(legacy_header, sizeof(*legacy_header), 1, in) != 1) {
        return 0;
    }

    if (sodium_memcmp(legacy_header->magic, SCIPHER_MAGIC, SCIPHER_MAGIC_LEN) != 0) {
        return 0;
    }

    memcpy(header->magic, legacy_header->magic, SCIPHER_MAGIC_LEN);
    header->version = HEADER_VERSION_LEGACY;
    header->kdf_id = KDF_LEGACY;
    sodium_memzero(header->salt, sizeof(header->salt));
    sodium_memzero(header->pwhash_opslimit, sizeof(header->pwhash_opslimit));
    sodium_memzero(header->pwhash_memlimit, sizeof(header->pwhash_memlimit));
    memcpy(header->stream_header, legacy_header->stream_header, sizeof(header->stream_header));
    *is_legacy = 1;
    return 1;
}

void header_prepare_encrypt(FileHeader *header, const AppContext *ctx) {
    memcpy(header->magic, SCIPHER_MAGIC, SCIPHER_MAGIC_LEN);
    header->version = HEADER_VERSION_CURRENT;
    header->kdf_id = (unsigned char) ctx->key_kdf;
    randombytes_buf(header->salt, sizeof(header->salt));
    kdf_default_pwhash_limits(header->pwhash_opslimit, header->pwhash_memlimit);
}
