#ifndef SECURE_CIPHER_PLATFORM_H
#define SECURE_CIPHER_PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

const char *platform_name(void);
int platform_secure_key_file(const char *key_path);

#ifdef __cplusplus
}
#endif

#endif
