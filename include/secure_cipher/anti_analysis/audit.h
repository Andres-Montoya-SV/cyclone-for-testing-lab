#ifndef SECURE_CIPHER_ANTI_ANALYSIS_AUDIT_H
#define SECURE_CIPHER_ANTI_ANALYSIS_AUDIT_H

#include "secure_cipher/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Lab-only: reports environment signals; does not alter execution. */
void audit_print_environment_report(void);

#ifdef __cplusplus
}
#endif

#endif
