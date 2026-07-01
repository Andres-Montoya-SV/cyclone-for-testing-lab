#ifndef SECURE_CIPHER_PATH_H
#define SECURE_CIPHER_PATH_H

#ifdef __cplusplus
extern "C" {
#endif

char *path_join_key_file(const char *keydir);
char *path_encrypted_output(const char *input_path);
char *path_decrypted_output(const char *input_path);
int path_ends_with(const char *str, const char *suffix);
int path_output_exists(const char *output_path);

#ifdef __cplusplus
}
#endif

#endif
