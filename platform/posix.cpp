#include <sys/stat.h>
#include <unistd.h>

#include "secure_cipher/platform/platform.h"

const char *platform_name(void) {
#if defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#elif defined(_WIN32)
    return "windows";
#else
    return "unknown";
#endif
}

int platform_secure_key_file(const char *key_path) {
    return chmod(key_path, 0600) == 0;
}
