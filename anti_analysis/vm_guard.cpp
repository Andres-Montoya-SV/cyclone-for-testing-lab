#include "secure_cipher/anti_analysis/vm_guard.h"

#include "secure_cipher/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#if defined(_WIN32)
#include <intrin.h>
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
#define VM_GUARD_HAVE_CPUID 1
#else
#define VM_GUARD_HAVE_CPUID 0
#endif

static void vm_guard_set_reason(char *reason, size_t reason_size, const char *message) {
    if (reason == NULL || reason_size == 0) {
        return;
    }

    snprintf(reason, reason_size, "%s", message != NULL ? message : "virtual machine detected");
}

static int str_contains_ci(const char *haystack, const char *needle) {
    size_t hay_len;
    size_t needle_len;

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }

    hay_len = strlen(haystack);
    needle_len = strlen(needle);
    if (needle_len > hay_len) {
        return 0;
    }

    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        size_t j = 0;
        while (j < needle_len && tolower((unsigned char) haystack[i + j]) == tolower((unsigned char) needle[j])) {
            j++;
        }
        if (j == needle_len) {
            return 1;
        }
    }

    return 0;
}

static int vm_string_indicates_virtualization(const char *value) {
    static const char *needles[] = {
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "kvm",
        "bochs",
        "parallels",
        "virtual machine",
        "virtualmac",
        "xen",
        "hyper-v",
        "microsoft corporation",
        "innotek",
        "bhyve",
        "acrn",
        "nutanix",
        "amazon ec2",
        "google compute",
        "digitalocean",
        NULL
    };

    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    for (int i = 0; needles[i] != NULL; i++) {
        if (str_contains_ci(value, needles[i])) {
            return 1;
        }
    }

    return 0;
}

#if defined(__linux__)
static int read_trimmed_line(const char *path, char *buffer, size_t buffer_size) {
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        return 0;
    }

    if (fgets(buffer, (int) buffer_size, file) == NULL) {
        fclose(file);
        return 0;
    }

    fclose(file);
    buffer[strcspn(buffer, "\r\n")] = '\0';

    while (buffer[0] != '\0' && isspace((unsigned char) buffer[strlen(buffer) - 1])) {
        buffer[strlen(buffer) - 1] = '\0';
    }

    return buffer[0] != '\0';
}

static int linux_dmi_indicates_vm(char *reason, size_t reason_size) {
    static const char *paths[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_vendor",
        NULL
    };

    for (int i = 0; paths[i] != NULL; i++) {
        char value[256] = "";

        if (!read_trimmed_line(paths[i], value, sizeof(value))) {
            continue;
        }

        if (vm_string_indicates_virtualization(value)) {
            char detail[320];
            snprintf(detail, sizeof(detail), "DMI %s reports '%s'", paths[i], value);
            vm_guard_set_reason(reason, reason_size, detail);
            return 1;
        }
    }

    return 0;
}

static int linux_cpuinfo_hypervisor_flag(char *reason, size_t reason_size) {
    FILE *file = fopen("/proc/cpuinfo", "r");
    char line[512];

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (str_contains_ci(line, "hypervisor")) {
            char detail[320];
            line[strcspn(line, "\r\n")] = '\0';
            snprintf(detail, sizeof(detail), "CPU hypervisor flag in /proc/cpuinfo: %s", line);
            vm_guard_set_reason(reason, reason_size, detail);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

static int linux_hypervisor_module_loaded(char *reason, size_t reason_size) {
    static const char *modules[] = {
        "vboxguest",
        "vboxsf",
        "vboxvideo",
        "vmw_balloon",
        "vmw_vmci",
        "vmw_vsock_vmci_transport",
        "vmxnet3",
        "virtio_pci",
        "virtio_net",
        "virtio_blk",
        "virtio_scsi",
        "xen_acpi_processor",
        "xen_blkfront",
        "xen_netfront",
        "hv_balloon",
        "hv_utils",
        "hv_vmbus",
        "hv_netvsc",
        "hv_storvsc",
        NULL
    };

    FILE *file = fopen("/proc/modules", "r");
    char line[512];

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        for (int i = 0; modules[i] != NULL; i++) {
            const size_t name_len = strlen(modules[i]);
            if (strncmp(line, modules[i], name_len) == 0
                && (line[name_len] == ' ' || line[name_len] == '\t')) {
                char detail[320];
                snprintf(detail, sizeof(detail), "Hypervisor guest module loaded: %s", modules[i]);
                vm_guard_set_reason(reason, reason_size, detail);
                fclose(file);
                return 1;
            }
        }
    }

    fclose(file);
    return 0;
}

static int linux_scsi_vendor_indicates_vm(char *reason, size_t reason_size) {
    FILE *file = fopen("/proc/scsi/scsi", "r");
    char line[512];

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (vm_string_indicates_virtualization(line)) {
            char detail[320];
            line[strcspn(line, "\r\n")] = '\0';
            snprintf(detail, sizeof(detail), "Virtual SCSI identity in /proc/scsi/scsi: %s", line);
            vm_guard_set_reason(reason, reason_size, detail);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}
#endif

#if VM_GUARD_HAVE_CPUID
static int cpuid_hypervisor_present(char *reason, size_t reason_size) {
    unsigned int eax = 0;
    unsigned int ebx = 0;
    unsigned int ecx = 0;
    unsigned int edx = 0;
    char vendor[13];

#if defined(_WIN32)
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    ecx = (unsigned int) cpu_info[2];
#else
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
#endif

    if ((ecx & (1U << 31)) == 0) {
        return 0;
    }

#if defined(_WIN32)
    __cpuid(cpu_info, 0x40000000);
    ebx = (unsigned int) cpu_info[1];
    ecx = (unsigned int) cpu_info[2];
    edx = (unsigned int) cpu_info[3];
#else
    eax = 0x40000000;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(eax));
#endif

    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';

    if (vendor[0] == '\0') {
        vm_guard_set_reason(reason, reason_size, "CPUID reports hypervisor present bit");
        return 1;
    }

    {
        char detail[320];
        snprintf(detail, sizeof(detail), "CPUID hypervisor vendor '%s'", vendor);
        vm_guard_set_reason(reason, reason_size, detail);
    }

    return 1;
}
#endif

#if defined(__APPLE__)
static int macos_hardware_model_indicates_vm(char *reason, size_t reason_size) {
    char model[256] = "";
    size_t model_len = sizeof(model);

    if (sysctlbyname("hw.model", model, &model_len, NULL, 0) != 0) {
        model_len = sizeof(model);
        if (sysctlbyname("hw.machine", model, &model_len, NULL, 0) != 0) {
            return 0;
        }
    }

    if (vm_string_indicates_virtualization(model) || str_contains_ci(model, "virtual")) {
        char detail[320];
        snprintf(detail, sizeof(detail), "Hardware model '%s'", model);
        vm_guard_set_reason(reason, reason_size, detail);
        return 1;
    }

    return 0;
}
#endif

#if defined(_WIN32)
static int windows_registry_value_contains_vm(HKEY root, const char *subkey, const char *value_name, char *reason, size_t reason_size) {
    HKEY key;
    char buffer[512];
    DWORD buffer_size = sizeof(buffer);
    DWORD type = 0;

    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return 0;
    }

    if (RegQueryValueExA(key, value_name, NULL, &type, (LPBYTE) buffer, &buffer_size) != ERROR_SUCCESS
        || (type != REG_SZ && type != REG_MULTI_SZ)) {
        RegCloseKey(key);
        return 0;
    }

    RegCloseKey(key);

    if (!vm_string_indicates_virtualization(buffer)) {
        return 0;
    }

    {
        char detail[320];
        snprintf(detail, sizeof(detail), "Registry %s\\%s = '%s'", subkey, value_name, buffer);
        vm_guard_set_reason(reason, reason_size, detail);
    }

    return 1;
}

static int windows_vm_devices_present(char *reason, size_t reason_size) {
    static const char *devices[] = {
        "\\\\.\\VBoxGuest",
        "\\\\.\\VBoxMiniRdrDN",
        "\\\\.\\VBoxTrayIPC",
        "\\\\.\\vmci",
        "\\\\.\\HGFS",
        NULL
    };

    for (int i = 0; devices[i] != NULL; i++) {
        HANDLE handle = CreateFileA(
            devices[i],
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (handle != INVALID_HANDLE_VALUE) {
            char detail[320];
            snprintf(detail, sizeof(detail), "Hypervisor device accessible: %s", devices[i]);
            CloseHandle(handle);
            vm_guard_set_reason(reason, reason_size, detail);
            return 1;
        }
    }

    return 0;
}
#endif

int vm_guard_is_virtual_machine(char *reason, size_t reason_size) {
#if defined(__linux__)
    if (linux_dmi_indicates_vm(reason, reason_size)) {
        return 1;
    }

    if (linux_cpuinfo_hypervisor_flag(reason, reason_size)) {
        return 1;
    }

    if (linux_hypervisor_module_loaded(reason, reason_size)) {
        return 1;
    }

    if (linux_scsi_vendor_indicates_vm(reason, reason_size)) {
        return 1;
    }
#endif

#if defined(__APPLE__)
    if (macos_hardware_model_indicates_vm(reason, reason_size)) {
        return 1;
    }
#endif

#if defined(_WIN32)
    if (windows_registry_value_contains_vm(
            HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System",
            "SystemBiosVersion",
            reason,
            reason_size
        )) {
        return 1;
    }

    if (windows_registry_value_contains_vm(
            HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System",
            "VideoBiosVersion",
            reason,
            reason_size
        )) {
        return 1;
    }

    if (windows_vm_devices_present(reason, reason_size)) {
        return 1;
    }
#endif

#if VM_GUARD_HAVE_CPUID
    if (cpuid_hypervisor_present(reason, reason_size)) {
        return 1;
    }
#endif

    return 0;
}

void vm_guard_exit_if_detected(void) {
    char reason[320];

    if (!vm_guard_is_virtual_machine(reason, sizeof(reason))) {
        return;
    }

    fprintf(stderr, "Refusing to run in a virtualized environment: %s\n", reason);
    fprintf(
        stderr,
        "Set %s=1 only in authorized lab environments to override this check.\n",
        VM_ALLOW_ENV
    );
    exit(VM_EXIT_CODE);
}
