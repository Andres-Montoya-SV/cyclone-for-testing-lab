#ifndef SECURE_CIPHER_ANTI_ANALYSIS_VM_GUARD_H
#define SECURE_CIPHER_ANTI_ANALYSIS_VM_GUARD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 when a virtualized environment is detected, 0 otherwise. */
int vm_guard_is_virtual_machine(char *reason, size_t reason_size);

/* Prints reason to stderr and terminates the process when VM is detected. */
void vm_guard_exit_if_detected(void);

#ifdef __cplusplus
}
#endif

#endif
