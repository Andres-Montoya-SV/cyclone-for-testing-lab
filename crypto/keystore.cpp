#include "secure_cipher/config.h"
#include "secure_cipher/crypto/keystore.h"

#include "secure_cipher/crypto/kdf.h"
#include "secure_cipher/path.h"
#include "secure_cipher/platform/platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int warn_insecure_key_permissions(const char *key_path, const struct stat *st) {
    mode_t exposed = st->st_mode & (S_IRWXG | S_IRWXO);

    if (exposed == 0) {
        return 1;
    }

    fprintf(
        stderr,
        "Warning: key file '%s' is readable or writable by group/other (mode %04o). "
        "Restrict to owner-only (chmod 600) for security.\n",
        key_path,
        (unsigned int) (st->st_mode & 07777)
    );
    return 1;
}

int keystore_load_passphrase(AppContext *ctx, const char *keydir) {
    if (keydir == NULL || keydir[0] == '\0') {
        fprintf(stderr, "Key directory not set. Use -k <dir> or export %s.\n", KEYDIR_ENV);
        return 0;
    }

    struct stat st;
    if (stat(keydir, &st) != 0) {
        fprintf(stderr, "Key directory '%s' not accessible: %s\n", keydir, strerror(errno));
        return 0;
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "'%s' is not a key directory.\n", keydir);
        return 0;
    }

    char *key_path = path_join_key_file(keydir);
    if (key_path == NULL) {
        fprintf(stderr, "Could not build key file path.\n");
        return 0;
    }

    if (stat(key_path, &st) != 0) {
        fprintf(
            stderr,
            "Key file '%s' not found. Run '%s keygen <keydir>' to create it.\n",
            key_path,
            ctx->program_name
        );
        free(key_path);
        return 0;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular key file.\n", key_path);
        free(key_path);
        return 0;
    }

    warn_insecure_key_permissions(key_path, &st);

    FILE *key_file = fopen(key_path, "rb");
    if (key_file == NULL) {
        fprintf(stderr, "Could not open key file '%s': %s\n", key_path, strerror(errno));
        free(key_path);
        return 0;
    }

    if (fseek(key_file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Could not read key file '%s'.\n", key_path);
        fclose(key_file);
        free(key_path);
        return 0;
    }

    const long file_size = ftell(key_file);
    if (file_size < 0) {
        fprintf(stderr, "Could not read key file '%s'.\n", key_path);
        fclose(key_file);
        free(key_path);
        return 0;
    }

    if (file_size == 0 || file_size > MAX_PASSPHRASE_LEN) {
        fprintf(stderr, "Key file '%s' must contain 1-%d bytes.\n", key_path, MAX_PASSPHRASE_LEN);
        fclose(key_file);
        free(key_path);
        return 0;
    }

    if (fseek(key_file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Could not read key file '%s'.\n", key_path);
        fclose(key_file);
        free(key_path);
        return 0;
    }

    char *buffer = (char *) sodium_malloc((size_t) file_size + 1);
    if (buffer == NULL) {
        fprintf(stderr, "Out of memory loading key file.\n");
        fclose(key_file);
        free(key_path);
        return 0;
    }

    size_t read_count = fread(buffer, 1, (size_t) file_size, key_file);
    fclose(key_file);
    free(key_path);

    if (read_count != (size_t) file_size) {
        fprintf(stderr, "Could not read key file.\n");
        sodium_memzero(buffer, (size_t) file_size + 1);
        sodium_free(buffer);
        return 0;
    }

    buffer[read_count] = '\0';
    while (read_count > 0 && (buffer[read_count - 1] == '\n' || buffer[read_count - 1] == '\r')) {
        buffer[--read_count] = '\0';
    }

    if (read_count == 0) {
        fprintf(stderr, "Key file is empty after trimming.\n");
        sodium_memzero(buffer, (size_t) file_size + 1);
        sodium_free(buffer);
        return 0;
    }

    if (!app_context_set_passphrase(ctx, buffer)) {
        sodium_memzero(buffer, (size_t) file_size + 1);
        sodium_free(buffer);
        return 0;
    }

    ctx->key_kdf = kdf_classify_key_material(ctx->passphrase, ctx->passphrase_len);

    sodium_memzero(buffer, (size_t) file_size + 1);
    sodium_free(buffer);
    return 1;
}

int keystore_init_keydir(const char *keydir) {
    if (keydir == NULL || keydir[0] == '\0') {
        fprintf(stderr, "Key directory path required.\n");
        return 0;
    }

    if (mkdir(keydir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Could not create key directory '%s': %s\n", keydir, strerror(errno));
        return 0;
    }

    struct stat st;
    if (stat(keydir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "'%s' is not a directory.\n", keydir);
        return 0;
    }

    char *key_path = path_join_key_file(keydir);
    if (key_path == NULL) {
        fprintf(stderr, "Could not build key file path.\n");
        return 0;
    }

    if (access(key_path, F_OK) == 0) {
        fprintf(stderr, "Key file already exists: %s\n", key_path);
        free(key_path);
        return 0;
    }

    unsigned char random_pass[KEYGEN_RANDOM_BYTES];
    randombytes_buf(random_pass, sizeof(random_pass));

    char encoded[KEYGEN_RANDOM_BYTES * 2 + 1];
    if (sodium_bin2hex(encoded, sizeof(encoded), random_pass, sizeof(random_pass)) == NULL) {
        fprintf(stderr, "Failed to generate key material.\n");
        sodium_memzero(random_pass, sizeof(random_pass));
        free(key_path);
        return 0;
    }

    sodium_memzero(random_pass, sizeof(random_pass));
    const size_t encoded_len = strlen(encoded);

    FILE *key_file = fopen(key_path, "wx");
    if (key_file == NULL) {
        fprintf(stderr, "Could not create key file '%s': %s\n", key_path, strerror(errno));
        sodium_memzero(encoded, sizeof(encoded));
        free(key_path);
        return 0;
    }

    if (fwrite(encoded, 1, encoded_len, key_file) != encoded_len) {
        fprintf(stderr, "Could not write key file '%s'.\n", key_path);
        fclose(key_file);
        remove(key_path);
        sodium_memzero(encoded, sizeof(encoded));
        free(key_path);
        return 0;
    }

    fclose(key_file);
    sodium_memzero(encoded, sizeof(encoded));

    if (!platform_secure_key_file(key_path)) {
        fprintf(stderr, "Warning: could not harden permissions on '%s'.\n", key_path);
    }

    printf("Key directory ready: %s\n", keydir);
    printf("Passphrase file: %s (owner read/write only)\n", key_path);
    printf("Keep this directory secure and out of untrusted data trees.\n");
    free(key_path);
    return 1;
}
