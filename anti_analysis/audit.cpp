#include "secure_cipher/anti_analysis/audit.h"

#include "secure_cipher/platform/platform.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

static const char *confidence_label(AuditConfidence confidence) {
    switch (confidence) {
    case AUDIT_CONF_HIGH:
        return "high";
    case AUDIT_CONF_MEDIUM:
        return "medium";
    case AUDIT_CONF_LOW:
        return "low";
    default:
        return "n/a";
    }
}

static void audit_finding_init(
    AuditFinding *finding,
    const char *name,
    const char *category,
    int detected,
    AuditConfidence confidence,
    const char *detail
) {
    finding->name = name;
    finding->category = category;
    finding->detected = detected;
    finding->confidence = detected ? confidence : AUDIT_CONF_NONE;
    snprintf(finding->detail, sizeof(finding->detail), "%s", detail != NULL ? detail : "");
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

static int name_looks_like_debugger(const char *name) {
    static const char *needles[] = {
        "gdb",
        "lldb",
        "debug",
        "frida",
        "strace",
        "ltrace",
        "radare",
        "r2",
        "ida",
        "x64dbg",
        "ollydbg",
        "windbg",
        "immunity",
        "hopper",
        NULL
    };

    for (int i = 0; needles[i] != NULL; i++) {
        if (str_contains_ci(name, needles[i])) {
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

static int read_linux_tracer_pid(int *tracer_pid_out) {
    FILE *file = fopen("/proc/self/status", "r");
    char line[256];

    if (file == NULL || tracer_pid_out == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            *tracer_pid_out = atoi(line + 10);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}
#endif

static AuditFinding audit_ptrace_tracer(void) {
    AuditFinding finding;

#if defined(__linux__)
    int tracer_pid = 0;
    if (read_linux_tracer_pid(&tracer_pid) && tracer_pid != 0) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "TracerPid=%d in /proc/self/status (process is being traced; strong debugger signal).",
            tracer_pid
        );
        audit_finding_init(&finding, "Ptrace tracer", "debugger", 1, AUDIT_CONF_HIGH, detail);
        return finding;
    }

    audit_finding_init(
        &finding,
        "Ptrace tracer",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "TracerPid is 0."
    );
    return finding;
#elif defined(__APPLE__)
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};

    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0 && (info.kp_proc.p_flag & P_TRACED) != 0) {
        audit_finding_init(
            &finding,
            "Ptrace tracer",
            "debugger",
            1,
            AUDIT_CONF_HIGH,
            "KERN_PROC reports P_TRACED on this process."
        );
        return finding;
    }

    audit_finding_init(
        &finding,
        "Ptrace tracer",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "No P_TRACED flag observed."
    );
    return finding;
#elif defined(_WIN32)
    if (IsDebuggerPresent()) {
        audit_finding_init(
            &finding,
            "Windows debugger API",
            "debugger",
            1,
            AUDIT_CONF_MEDIUM,
            "IsDebuggerPresent() returned TRUE."
        );
        return finding;
    }

    audit_finding_init(
        &finding,
        "Windows debugger API",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "IsDebuggerPresent() returned FALSE."
    );
    return finding;
#else
    audit_finding_init(
        &finding,
        "Ptrace tracer",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "Not implemented on this platform."
    );
    return finding;
#endif
}

static AuditFinding audit_parent_process(void) {
    AuditFinding finding;
    char parent_name[256];

#if defined(__linux__)
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", getppid());

    if (!read_trimmed_line(proc_path, parent_name, sizeof(parent_name))) {
        audit_finding_init(
            &finding,
            "Parent process",
            "debugger",
            0,
            AUDIT_CONF_NONE,
            "Could not read parent process name from /proc."
        );
        return finding;
    }
#elif defined(__APPLE__)
    if (proc_name(getppid(), parent_name, sizeof(parent_name)) <= 0) {
        audit_finding_init(
            &finding,
            "Parent process",
            "debugger",
            0,
            AUDIT_CONF_NONE,
            "proc_name() failed for parent PID."
        );
        return finding;
    }
#elif defined(_WIN32)
    audit_finding_init(
        &finding,
        "Parent process",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "Parent process name inspection not implemented on Windows."
    );
    return finding;
#else
    audit_finding_init(
        &finding,
        "Parent process",
        "debugger",
        0,
        AUDIT_CONF_NONE,
        "Not implemented on this platform."
    );
    return finding;
#endif

#if defined(__linux__) || defined(__APPLE__)
    if (name_looks_like_debugger(parent_name)) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "Parent PID %d name '%s' matches common debugger tooling.",
            getppid(),
            parent_name
        );
        audit_finding_init(&finding, "Parent process", "debugger", 1, AUDIT_CONF_MEDIUM, detail);
        return finding;
    }

    {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "Parent PID %d name '%s' does not match known debugger patterns.",
            getppid(),
            parent_name
        );
        audit_finding_init(&finding, "Parent process", "debugger", 0, AUDIT_CONF_NONE, detail);
    }
    return finding;
#endif
}

#if defined(__linux__)
static int dmi_value_indicates_vm(const char *value) {
    static const char *needles[] = {
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "kvm",
        "bochs",
        "parallels",
        "virtual machine",
        "xen",
        "hyper-v",
        "microsoft corporation",
        "innotek",
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
#endif

static AuditFinding audit_vm_dmi(void) {
    AuditFinding finding;

#if defined(__linux__)
    char product[256] = "";
    char vendor[256] = "";
    int product_vm = 0;
    int vendor_vm = 0;

    product_vm = read_trimmed_line("/sys/class/dmi/id/product_name", product, sizeof(product))
        && dmi_value_indicates_vm(product);
    vendor_vm = read_trimmed_line("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor))
        && dmi_value_indicates_vm(vendor);

    if (product_vm || vendor_vm) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "DMI product='%s', vendor='%s'.",
            product_vm ? product : "(ok)",
            vendor_vm ? vendor : "(ok)"
        );
        audit_finding_init(&finding, "Hardware identity (DMI)", "virtualization", 1, AUDIT_CONF_HIGH, detail);
        return finding;
    }

    if (read_trimmed_line("/sys/class/dmi/id/product_name", product, sizeof(product))
        || read_trimmed_line("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor))) {
        char detail[320];
        snprintf(detail, sizeof(detail), "DMI product='%s', vendor='%s'.", product, vendor);
        audit_finding_init(&finding, "Hardware identity (DMI)", "virtualization", 0, AUDIT_CONF_NONE, detail);
        return finding;
    }

    audit_finding_init(
        &finding,
        "Hardware identity (DMI)",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "DMI sysfs paths unavailable (common in containers)."
    );
    return finding;
#else
    audit_finding_init(
        &finding,
        "Hardware identity (DMI)",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "DMI inspection is only implemented on Linux."
    );
    return finding;
#endif
}

static AuditFinding audit_vm_cpu(void) {
    AuditFinding finding;

#if defined(__linux__)
    FILE *file = fopen("/proc/cpuinfo", "r");
    char line[512];
    int hypervisor_flag = 0;
    char hypervisor_line[320] = "";

    if (file == NULL) {
        audit_finding_init(
            &finding,
            "CPU hypervisor flag",
            "virtualization",
            0,
            AUDIT_CONF_NONE,
            "Could not read /proc/cpuinfo."
        );
        return finding;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (str_contains_ci(line, "hypervisor")) {
            hypervisor_flag = 1;
            snprintf(hypervisor_line, sizeof(hypervisor_line), "%s", line);
            hypervisor_line[strcspn(hypervisor_line, "\r\n")] = '\0';
            break;
        }
    }

    fclose(file);

    if (hypervisor_flag) {
        char detail[320];
        snprintf(detail, sizeof(detail), "Found in /proc/cpuinfo: %s", hypervisor_line);
        audit_finding_init(&finding, "CPU hypervisor flag", "virtualization", 1, AUDIT_CONF_HIGH, detail);
        return finding;
    }

    audit_finding_init(
        &finding,
        "CPU hypervisor flag",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "No hypervisor CPU flag in /proc/cpuinfo."
    );
    return finding;
#elif defined(__APPLE__)
    char model[256] = "";
    size_t model_len = sizeof(model);

    if (sysctlbyname("hw.model", model, &model_len, NULL, 0) != 0) {
        char machine[256] = "";
        size_t machine_len = sizeof(machine);
        if (sysctlbyname("hw.machine", machine, &machine_len, NULL, 0) == 0) {
            snprintf(model, sizeof(model), "%s", machine);
        }
    }

    if (model[0] != '\0') {
        if (str_contains_ci(model, "virtual") || str_contains_ci(model, "vmware")) {
            char detail[320];
            snprintf(detail, sizeof(detail), "Hardware identifier '%s'.", model);
            audit_finding_init(&finding, "Hardware model", "virtualization", 1, AUDIT_CONF_MEDIUM, detail);
            return finding;
        }

        char detail[320];
        snprintf(detail, sizeof(detail), "Hardware identifier '%s'.", model);
        audit_finding_init(&finding, "Hardware model", "virtualization", 0, AUDIT_CONF_NONE, detail);
        return finding;
    }

    audit_finding_init(
        &finding,
        "Hardware model",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "Could not read hw.model or hw.machine."
    );
    return finding;
#else
    audit_finding_init(
        &finding,
        "CPU hypervisor flag",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "Not implemented on this platform."
    );
    return finding;
#endif
}

static AuditFinding audit_vm_memory(void) {
    AuditFinding finding;
    uint64_t mem_bytes = 0;

#if defined(__linux__)
    char line[256];
    FILE *file = fopen("/proc/meminfo", "r");
    if (file != NULL) {
        while (fgets(line, sizeof(line), file) != NULL) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                mem_bytes = (uint64_t) strtoull(line + 9, NULL, 10) * 1024ULL;
                break;
            }
        }
        fclose(file);
    }
#elif defined(__APPLE__)
    size_t mem_size = sizeof(mem_bytes);
    int mib[2] = {CTL_HW, HW_MEMSIZE};
    if (sysctl(mib, 2, &mem_bytes, &mem_size, NULL, 0) != 0) {
        mem_bytes = 0;
    }
#elif defined(_WIN32)
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        mem_bytes = status.ullTotalPhys;
    }
#endif

    if (mem_bytes > 0 && mem_bytes < (uint64_t) 2 * 1024 * 1024 * 1024) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "Physical memory %.2f GiB (< 2 GiB; weak sandbox/VM hint, many false positives).",
            mem_bytes / (1024.0 * 1024.0 * 1024.0)
        );
        audit_finding_init(&finding, "Physical memory", "virtualization", 1, AUDIT_CONF_LOW, detail);
        return finding;
    }

    if (mem_bytes > 0) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "Physical memory %.2f GiB.",
            mem_bytes / (1024.0 * 1024.0 * 1024.0)
        );
        audit_finding_init(&finding, "Physical memory", "virtualization", 0, AUDIT_CONF_NONE, detail);
        return finding;
    }

    audit_finding_init(
        &finding,
        "Physical memory",
        "virtualization",
        0,
        AUDIT_CONF_NONE,
        "Could not determine installed memory."
    );
    return finding;
}

static AuditFinding audit_env_vars(void) {
    AuditFinding finding;
    static const char *vars[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "LD_PRELOAD",
        "LD_AUDIT",
        "ASAN_OPTIONS",
        "LSAN_OPTIONS",
        "MSAN_OPTIONS",
        "UBSAN_OPTIONS",
        "TSAN_OPTIONS",
        "_MS_HOOK",
        "FRIDA_SERVER",
        NULL
    };

    char hits[320] = "";
    int hit_count = 0;

    for (int i = 0; vars[i] != NULL; i++) {
        const char *value = getenv(vars[i]);
        if (value == NULL || value[0] == '\0') {
            continue;
        }

        if (hit_count > 0) {
            strncat(hits, ", ", sizeof(hits) - strlen(hits) - 1);
        }

        strncat(hits, vars[i], sizeof(hits) - strlen(hits) - 1);
        hit_count++;
    }

    if (hit_count > 0) {
        char detail[320];
        snprintf(
            detail,
            sizeof(detail),
            "Set analysis-related variables: %s.",
            hits
        );
        audit_finding_init(
            &finding,
            "Analysis environment variables",
            "analysis_tooling",
            1,
            hit_count >= 2 ? AUDIT_CONF_HIGH : AUDIT_CONF_MEDIUM,
            detail
        );
        return finding;
    }

    audit_finding_init(
        &finding,
        "Analysis environment variables",
        "analysis_tooling",
        0,
        AUDIT_CONF_NONE,
        "No common instrumentation or hooking variables detected."
    );
    return finding;
}

static AuditFinding audit_privilege_level(void) {
    AuditFinding finding;

#if defined(_WIN32)
    if (IsUserAnAdmin()) {
        audit_finding_init(
            &finding,
            "Privilege level",
            "host_context",
            1,
            AUDIT_CONF_LOW,
            "Process appears to run with administrative rights."
        );
        return finding;
    }
#else
    if (geteuid() == 0) {
        audit_finding_init(
            &finding,
            "Privilege level",
            "host_context",
            1,
            AUDIT_CONF_LOW,
            "Effective UID is 0 (root)."
        );
        return finding;
    }
#endif

    audit_finding_init(
        &finding,
        "Privilege level",
        "host_context",
        0,
        AUDIT_CONF_NONE,
        "Not running with elevated privileges."
    );
    return finding;
}

static void print_finding(const AuditFinding *finding) {
    printf(
        "[%s] %s (%s",
        finding->detected ? "signal" : "clear",
        finding->name,
        finding->category
    );

    if (finding->detected) {
        printf(", confidence=%s", confidence_label(finding->confidence));
    }

    printf(")\n    %s\n", finding->detail);
}

void audit_print_environment_report(void) {
    AuditFinding findings[] = {
        audit_ptrace_tracer(),
        audit_parent_process(),
        audit_vm_dmi(),
        audit_vm_cpu(),
        audit_vm_memory(),
        audit_env_vars(),
        audit_privilege_level(),
    };

    size_t signal_count = 0;
    size_t high_confidence = 0;

    printf("=== Environment audit report ===\n");
    printf("Platform: %s | PID: %d | PPID: %d\n", platform_name(), (int) getpid(), (int) getppid());
    printf("Educational report only. Findings do not change program behavior.\n");
    printf("Blue teams correlate multiple medium/high signals; single low signals are often noisy.\n\n");

    for (size_t i = 0; i < sizeof(findings) / sizeof(findings[0]); i++) {
        print_finding(&findings[i]);
        if (findings[i].detected) {
            signal_count++;
            if (findings[i].confidence >= AUDIT_CONF_HIGH) {
                high_confidence++;
            }
        }
    }

    printf(
        "\nSummary: %zu signal(s), %zu high-confidence. "
        "Treat isolated low-confidence hits as weak IOCs.\n",
        signal_count,
        high_confidence
    );
}
