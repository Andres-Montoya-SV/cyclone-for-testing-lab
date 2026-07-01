# Architecture & how the code works

This document describes what **secure_cipher** does internally and how the modules fit together. It is written for portfolio reviewers and authorized lab readers.

## What the program does

`secure_cipher` is a command-line program that:

1. Loads a **machine key** from an external directory (`keys/passphrase`, created by `keygen`)
2. **Encrypts** files or directory trees into `.enc` files using authenticated streaming encryption
3. Optionally **removes** the original plaintext after a successful encrypt
4. **Decrypts** `.enc` files back to their original names
5. Can run a **sim-lock** simulation (encrypt directory + drop recovery instructions) when `--disclaimer` is set
6. Can print an **environment audit** (`--audit-env`) or **refuse to run in a VM** (VM guard)

It is designed to behave like a simplified file-locking lab sample, not like production ransomware.

---

## High-level flow

```
main.cpp
  ├── cli/parser.cpp          Parse argv, flags, keydir, thread count
  ├── vm_guard.cpp            Exit if virtualization detected (unless overridden)
  ├── keystore.cpp            Load or generate machine key material
  └── command dispatch
        ├── encrypt.cpp / decrypt.cpp   Per-file crypto + path handling
        ├── work_pool.cpp               Parallel directory walks
        └── stream_io.cpp               Chunked read/write + buffering
```

### Startup sequence (`main.cpp`)

1. Initialize `AppContext` and libsodium
2. Parse CLI options (`-k`, `-j`, `--dry-run`, `--disclaimer`, `--audit-env`, …)
3. Resolve worker thread count (CPU count or `SECURE_CIPHER_THREADS`)
4. Run **VM guard** unless `--audit-env` or `SECURE_CIPHER_ALLOW_VM=1`
5. Optionally print audit report (`--audit-env`)
6. For crypto commands: load passphrase from keydir via `keystore_load_passphrase`
7. Dispatch `encrypt`, `encrypt-dir`, `decrypt`, `sim-lock`, or `keygen`

---

## Module reference

### CLI (`cli/parser.cpp`)

Parses arguments into `CliOptions` and updates `AppContext` (dry-run, disclaimer, worker threads). Invalid combinations print usage and exit.

### Application context (`crypto/context.cpp`)

`AppContext` holds:

- Passphrase / machine key (in secure memory via `sodium_malloc`)
- KDF mode, dry-run flag, disclaimer flag, worker thread count

`app_context_resolve_threads()` picks thread count from `-j`, env, or `std::thread::hardware_concurrency()`.

### Keystore (`crypto/keystore.cpp`)

- **`keygen`**: writes a 32-byte random key as 64 hex chars to `<keydir>/passphrase`
- **Load**: reads key material and classifies it (hex machine key vs human passphrase)

Machine keys skip slow Argon2 at runtime; human passphrases use Argon2id.

### Key derivation (`crypto/kdf.cpp`)

Each encrypted file has a **per-file salt** in its header. The stream key is derived from:

| `kdf_id` | Meaning |
|----------|---------|
| `KDF_LEGACY` | Oldest format compatibility |
| `KDF_ARGON2ID` | Argon2id from human passphrase + salt |
| `KDF_GENERICHASH` | Legacy v2 generichash path |
| `KDF_MACHINE_BLOB` | 32-byte hex machine key + generichash domain step |

Domain separation string: `SCIPHER/XChaCha20-Poly1305/file-key/v1`

**AAD (additional authenticated data)** on v3+ binds the ciphertext to header fields (version, kdf_id, salt, Argon2 limits) so header tampering fails decryption.

### File header (`crypto/header.cpp`, `types.h`)

On-disk layout (v3):

```
magic "SCIPH" | version | kdf_id | salt | opslimit | memlimit | stream_header
```

`stream_header` is the libsodium secretstream push header (24 bytes). Legacy v1/v2 headers are still readable for decrypt.

### Encryption path (`crypto/encrypt.cpp` + `crypto/stream_io.cpp`)

For each file:

1. Build output path: `file.txt` → `file.txt.enc` (refuses if output already exists)
2. `header_prepare_encrypt()` — random salt, version, KDF metadata
3. `stream_io_encrypt_payload()`:
   - Derive per-file key
   - `crypto_secretstream_xchacha20poly1305_init_push`
   - Write `FileHeader` to output
   - Read plaintext in chunks (4 KiB), push each chunk with AAD, fwrite ciphertext
4. Optionally `remove()` plaintext

**Directory mode** (`work_pool.cpp`): `nftw` collects paths, then a thread pool calls `encrypt_file` in parallel. Logging uses mutexes.

### Decryption path (`crypto/decrypt.cpp` + `crypto/stream_io.cpp`)

1. Open `.enc`, `header_read()` (supports legacy)
2. Derive key + AAD (if v3+)
3. `stream_io_decrypt_payload()` — pull loop until `TAG_FINAL`
4. Write decrypted file; optionally remove `.enc`

### Stream I/O (`crypto/stream_io.cpp`)

- Adaptive **stdio buffer** size (larger for big files)
- Linux: `posix_fadvise(SEQUENTIAL)` on input
- Encrypt/decrypt loops wrap libsodium secretstream push/pull
- Cleans up `setvbuf` buffers before fclose (buffer lifetime safety)

### Path helpers (`crypto/path.cpp`)

Encrypted/decrypted output naming, `.enc` suffix checks, recovery filename constant.

### Work pool (`crypto/work_pool.cpp`)

C++ thread pool with atomic job index. Collects files via `nftw`, filters `.enc` / recovery instructions on encrypt walks. Reports success/failure counts.

### Environment audit (`anti_analysis/audit.cpp`)

**Report only** — does not change behavior. Checks:

- Debugger / tracer (Linux `TracerPid`, macOS `P_TRACED`, Windows stub)
- Parent process name heuristics
- VM hints (DMI, cpuinfo hypervisor flag, hardware model, low RAM)
- Analysis env vars (`LD_PRELOAD`, sanitizers, `FRIDA_SERVER`, …)
- Privilege level

Each finding has a confidence level for blue-team discussion.

### VM guard (`anti_analysis/vm_guard.cpp`)

**Active exit** (unlike audit). Detects:

- Linux: DMI strings, cpuinfo hypervisor flag, guest kernel modules (`vboxguest`, `virtio_*`, `vmw_*`, `hv_*`), SCSI vendor strings
- macOS: `hw.model` / virtual machine strings
- Windows: BIOS registry strings, hypervisor device paths
- x86: CPUID hypervisor bit + vendor leaf

Exits with code `86` unless `SECURE_CIPHER_ALLOW_VM=1` or `--audit-env` (audit-only pass).

### Platform (`platform/*.cpp`)

`platform_name()` and key-file permission helpers. macOS/Linux/Windows stubs for future OS-specific behavior.

---

## Encrypted file format (conceptual)

```
┌─────────────────────────────────────┐
│ FileHeader (magic, salt, KDF, …)    │
├─────────────────────────────────────┤
│ secretstream frame 1                │
│ secretstream frame 2                │
│ …                                   │
│ secretstream frame N (TAG_FINAL)    │
└─────────────────────────────────────┘
```

Each frame is produced by one `push` call; AAD authenticates the header on every chunk (v3+).

---

## Threading model

- **One secretstream state per file** — encryption inside a file is sequential
- **Parallelism across files** in directory mode via `work_pool`
- `AppContext` and key material are read-only during worker execution; each thread opens its own `FILE*`

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `SECURE_CIPHER_KEYDIR` | Default key directory |
| `SECURE_CIPHER_THREADS` | Default worker count |
| `SECURE_CIPHER_PWHASH` | Argon2 cost profile for new files |
| `SECURE_CIPHER_ALLOW_VM` | Skip VM guard exit |

---

## Build system

Single `Makefile`: C++17, `-pthread`, libsodium via `pkg-config`, `-lproc` on macOS for `proc_name()` in audit.

---

## Security caveats (portfolio honesty)

- This is a **learning project**, not audited cryptography or malware research grade
- Keys are stored **outside** ciphertext in `keys/passphrase`
- VM guard and audit checks are **educational** and bypassable
- Do not infer real-world attacker sophistication from this sample

See [NOTICE.md](../NOTICE.md) for permitted use.
