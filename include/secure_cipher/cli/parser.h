#ifndef SECURE_CIPHER_CLI_PARSER_H
#define SECURE_CIPHER_CLI_PARSER_H

#include "secure_cipher/context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum CliCommand {
    CLI_CMD_NONE = 0,
    CLI_CMD_KEYGEN,
    CLI_CMD_ENCRYPT,
    CLI_CMD_ENCRYPT_DIR,
    CLI_CMD_DECRYPT,
    CLI_CMD_SIM_LOCK,
    CLI_CMD_AUDIT_ENV
} CliCommand;

typedef struct CliOptions {
    CliCommand command;
    const char *keydir;
    const char *path;
    int audit_env;
} CliOptions;

int cli_parse(int argc, char *argv[], AppContext *ctx, CliOptions *options);
void cli_print_usage(const char *program);

#ifdef __cplusplus
}
#endif

#endif
