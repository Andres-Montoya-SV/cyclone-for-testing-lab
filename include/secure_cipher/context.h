#ifndef SECURE_CIPHER_CONTEXT_H
#define SECURE_CIPHER_CONTEXT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppContext {
    char *passphrase;
    size_t passphrase_len;
    int key_kdf;
    int dry_run;
    int disclaimer_accepted;
    int worker_threads;
    const char *program_name;
} AppContext;

void app_context_init(AppContext *ctx, const char *program_name);
void app_context_clear(AppContext *ctx);
void app_context_resolve_threads(AppContext *ctx);
int app_context_set_passphrase(AppContext *ctx, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif
