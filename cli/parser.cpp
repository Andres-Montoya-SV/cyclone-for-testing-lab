#include "secure_cipher/cli/parser.h"

#include "secure_cipher/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cli_print_usage(const char *program) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s [-k <keydir>] [-j <threads>] [--dry-run] [--disclaimer] [--audit-env] "
        "<encrypt|encrypt-dir|decrypt|sim-lock> <file_or_dir_path>\n"
        "  %s keygen <keydir>\n"
        "\n"
        "  -k <keydir> / %s     passphrase file at <keydir>/%s\n"
        "  -j <threads> / %s    parallel workers for directory operations (default: CPU count)\n"
        "  --dry-run             print actions without writing or deleting\n"
        "  --disclaimer          acknowledge simulation terms for sim-lock\n"
        "  --audit-env           print environment analysis report (lab only)\n"
        "\n"
        "VM guard: exits when virtualization is detected (%s overrides in lab).\n"
        "\n"
        "Crypto: XChaCha20-Poly1305 secretstream, Argon2id KDF, header-bound AAD.\n"
        "  %s=interactive|moderate|sensitive controls Argon2 cost for new files.\n",
        program,
        program,
        KEYDIR_ENV,
        KEY_FILENAME,
        THREADS_ENV,
        VM_ALLOW_ENV,
        PWHASH_ENV
    );
}

int cli_parse(int argc, char *argv[], AppContext *ctx, CliOptions *options) {
    int argi = 1;

    memset(options, 0, sizeof(*options));

    while (argi < argc) {
        if (strcmp(argv[argi], "-k") == 0) {
            if (argi + 1 >= argc) {
                return 0;
            }

            options->keydir = argv[argi + 1];
            argi += 2;
            continue;
        }

        if (strcmp(argv[argi], "-j") == 0) {
            if (argi + 1 >= argc) {
                return 0;
            }

            char *end = NULL;
            const long parsed = strtol(argv[argi + 1], &end, 10);
            if (end == argv[argi + 1] || *end != '\0' || parsed < 1 || parsed > MAX_WORKER_THREADS) {
                return 0;
            }

            ctx->worker_threads = (int) parsed;
            argi += 2;
            continue;
        }

        if (strcmp(argv[argi], "--dry-run") == 0) {
            ctx->dry_run = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "--disclaimer") == 0) {
            ctx->disclaimer_accepted = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "--audit-env") == 0) {
            options->audit_env = 1;
            argi += 1;
            continue;
        }

        break;
    }

    if (options->keydir == NULL) {
        options->keydir = getenv(KEYDIR_ENV);
    }

    if (argi >= argc) {
        return 0;
    }

    const char *mode = argv[argi++];

    if (strcmp(mode, "keygen") == 0) {
        if (argi >= argc) {
            return 0;
        }

        options->command = CLI_CMD_KEYGEN;
        options->path = argv[argi++];
        return argi == argc;
    }

    if (argi >= argc) {
        return 0;
    }

    options->path = argv[argi++];

    if (argi != argc) {
        return 0;
    }

    if (strcmp(mode, "encrypt") == 0) {
        options->command = CLI_CMD_ENCRYPT;
    } else if (strcmp(mode, "encrypt-dir") == 0) {
        options->command = CLI_CMD_ENCRYPT_DIR;
    } else if (strcmp(mode, "decrypt") == 0) {
        options->command = CLI_CMD_DECRYPT;
    } else if (strcmp(mode, "sim-lock") == 0) {
        options->command = CLI_CMD_SIM_LOCK;
    } else {
        return 0;
    }

    return 1;
}
