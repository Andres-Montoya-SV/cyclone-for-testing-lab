#include "secure_cipher/platform/platform.h"

#ifdef _WIN32
#include <windows.h>
#endif

/* Windows-specific hooks can be added here. */

#ifdef _WIN32
int platform_secure_key_file(const char *key_path) {
    (void) key_path;
    return 1;
}
#endif
