#include "secure_cipher/config.h"
#include "secure_cipher/context.h"

#include <cstdlib>
#include <sodium.h>
#include <string.h>
#include <thread>

void app_context_init(AppContext *ctx, const char *program_name) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->key_kdf = KDF_ARGON2ID;
    ctx->program_name = program_name;
    ctx->worker_threads = DEFAULT_WORKER_THREADS;
}

static int parse_thread_count(const char *value) {
    char *end = NULL;
    long parsed;

    if (value == NULL || *value == '\0') {
        return 0;
    }

    parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 1 || parsed > MAX_WORKER_THREADS) {
        return 0;
    }

    return (int) parsed;
}

void app_context_resolve_threads(AppContext *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->worker_threads <= 0) {
        const char *env = getenv(THREADS_ENV);
        if (env != NULL) {
            const int env_threads = parse_thread_count(env);
            if (env_threads > 0) {
                ctx->worker_threads = env_threads;
            }
        }
    }

    if (ctx->worker_threads <= 0) {
        const unsigned int hw = std::thread::hardware_concurrency();
        ctx->worker_threads = (hw > 0) ? (int) hw : 4;
    }

    if (ctx->worker_threads > MAX_WORKER_THREADS) {
        ctx->worker_threads = MAX_WORKER_THREADS;
    }

    if (ctx->worker_threads < 1) {
        ctx->worker_threads = 1;
    }
}

void app_context_clear(AppContext *ctx) {
    if (ctx->passphrase != NULL) {
        sodium_memzero(ctx->passphrase, ctx->passphrase_len + 1);
        sodium_free(ctx->passphrase);
        ctx->passphrase = NULL;
    }

    ctx->passphrase_len = 0;
}

int app_context_set_passphrase(AppContext *ctx, const char *passphrase) {
    size_t len;

    if (ctx == NULL || passphrase == NULL) {
        return 0;
    }

    len = strlen(passphrase);
    if (len == 0) {
        return 0;
    }

    if (ctx->passphrase != NULL) {
        sodium_memzero(ctx->passphrase, ctx->passphrase_len + 1);
        sodium_free(ctx->passphrase);
        ctx->passphrase = NULL;
        ctx->passphrase_len = 0;
    }

    ctx->passphrase = (char *) sodium_malloc(len + 1);
    if (ctx->passphrase == NULL) {
        return 0;
    }

    memcpy(ctx->passphrase, passphrase, len + 1);
    ctx->passphrase_len = len;
    return 1;
}
