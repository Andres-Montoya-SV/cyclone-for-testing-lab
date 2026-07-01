#include "secure_cipher/config.h"
#include "secure_cipher/path.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char *path_join_key_file(const char *keydir) {
    size_t keydir_len = strlen(keydir);
    size_t needs_slash = (keydir_len > 0 && keydir[keydir_len - 1] != '/') ? 1 : 0;
    size_t path_size = keydir_len + needs_slash + strlen(KEY_FILENAME) + 1;
    char *path = (char *) malloc(path_size);

    if (path == NULL) {
        return NULL;
    }

    if (snprintf(
            path,
            path_size,
            needs_slash ? "%s/%s" : "%s%s",
            keydir,
            KEY_FILENAME
        ) >= (int) path_size) {
        free(path);
        return NULL;
    }

    return path;
}

char *path_encrypted_output(const char *input_path) {
    size_t len = strlen(input_path);
    size_t out_size = len + 4 + 1;
    char *output_path = (char *) malloc(out_size);

    if (output_path == NULL) {
        return NULL;
    }

    if (snprintf(output_path, out_size, "%s.enc", input_path) >= (int) out_size) {
        free(output_path);
        return NULL;
    }

    return output_path;
}

char *path_decrypted_output(const char *input_path) {
    size_t len = strlen(input_path);

    if (path_ends_with(input_path, ".enc")) {
        size_t base_len = len - 4;
        char *output_path = (char *) malloc(base_len + 1);

        if (output_path == NULL) {
            return NULL;
        }

        memcpy(output_path, input_path, base_len);
        output_path[base_len] = '\0';
        return output_path;
    }

    size_t out_size = len + 4 + 1;
    char *output_path = (char *) malloc(out_size);

    if (output_path == NULL) {
        return NULL;
    }

    if (snprintf(output_path, out_size, "%s.dec", input_path) >= (int) out_size) {
        free(output_path);
        return NULL;
    }

    return output_path;
}

int path_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len) {
        return 0;
    }

    return memcmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

int path_output_exists(const char *output_path) {
    struct stat st;

    if (stat(output_path, &st) == 0) {
        fprintf(stderr, "Refusing to overwrite existing file: '%s'\n", output_path);
        return 1;
    }

    if (errno != ENOENT) {
        fprintf(
            stderr,
            "Could not check output path '%s': %s\n",
            output_path,
            strerror(errno)
        );
        return 1;
    }

    return 0;
}
