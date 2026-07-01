#ifndef SECURE_CIPHER_TYPES_H
#define SECURE_CIPHER_TYPES_H

#include "secure_cipher/config.h"

typedef struct FileHeader {
    unsigned char magic[SCIPHER_MAGIC_LEN];
    unsigned char version;
    unsigned char kdf_id;
    unsigned char salt[FILE_SALT_BYTES];
    unsigned char pwhash_opslimit[4];
    unsigned char pwhash_memlimit[4];
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
} FileHeader;

typedef struct FileHeaderLegacy {
    unsigned char magic[SCIPHER_MAGIC_LEN];
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
} FileHeaderLegacy;

typedef enum AuditConfidence {
    AUDIT_CONF_NONE = 0,
    AUDIT_CONF_LOW,
    AUDIT_CONF_MEDIUM,
    AUDIT_CONF_HIGH
} AuditConfidence;

typedef struct AuditFinding {
    const char *name;
    const char *category;
    int detected;
    AuditConfidence confidence;
    char detail[320];
} AuditFinding;

#endif
