# secure_cipher

Educational file-encryption lab tool for cybersecurity training. It simulates directory-level file locking with real cryptography (libsodium) so blue teams can practice detection, containment, and recovery in controlled environments.

---

> **Portfolio notice — read before anything else**
>
> This repository is on GitHub **only for my personal portfolio**. It is **not** licensed for redistribution, republishing, or use against any system or person without explicit written permission from me.
>
> Parts of the code were **improved and documented with AI assistance**; see [NOTICE.md](NOTICE.md).
>
> Technical documentation: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

> **Authorized use only.** Run only in isolated lab VMs or dedicated training hosts with explicit permission. Do not deploy against real user data or production systems.

## Features

- **Encrypt / decrypt** single files or entire directories (`.enc` output, optional plaintext removal)
- **sim-lock** mode with recovery instructions (`--disclaimer` required)
- **XChaCha20-Poly1305** secretstream, **Argon2id** KDF, per-file salt, header-bound AAD (v3)
- **Parallel directory processing** (`-j` / `SECURE_CIPHER_THREADS`)
- **Buffered I/O** for large files
- **Environment audit** (`--audit-env`) for blue-team exercises
- **VM guard** — exits when virtualization is detected (override with `SECURE_CIPHER_ALLOW_VM=1` in lab)

## Documentation

| Document | Contents |
|----------|----------|
| [NOTICE.md](NOTICE.md) | Portfolio-only terms, no redistribution, AI disclosure |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the code works — modules, crypto flow, threading |
| [keys/README.md](keys/README.md) | Key generation and usage |

## Requirements

- C++17 compiler (`g++` or `clang++`)
- [libsodium](https://libsodium.gitbook.io/doc/)
- `pkg-config`
- macOS: Xcode CLI tools (uses `-lproc` for process inspection)

### Install libsodium

**macOS (Homebrew)**

```bash
brew install libsodium pkg-config
```

**Debian / Ubuntu**

```bash
sudo apt-get install libsodium-dev pkg-config build-essential
```

## Build

```bash
make
```

Produces the `secure_cipher` binary in the project root.

```bash
make clean   # remove binary and object files
```

## Quick start

```bash
# 1. Build
make

# 2. Create a key (once per lab machine)
./secure_cipher keygen ./keys

# 3. Encrypt sample data
./secure_cipher -k ./keys encrypt-dir ./data

# 4. Decrypt to restore
./secure_cipher -k ./keys decrypt ./data
```

### sim-lock (simulation)

```bash
./secure_cipher -k ./keys --disclaimer sim-lock ./data
```

Writes `RECOVERY_INSTRUCTIONS.txt` in the target directory.

## Usage

```
./secure_cipher [-k <keydir>] [-j <threads>] [--dry-run] [--disclaimer] [--audit-env] \
  <encrypt|encrypt-dir|decrypt|sim-lock> <path>

./secure_cipher keygen <keydir>
```

| Flag / env | Description |
|------------|-------------|
| `-k <keydir>` | Key directory containing `passphrase` |
| `SECURE_CIPHER_KEYDIR` | Same as `-k` |
| `-j <n>` | Worker threads for directory ops (1–32) |
| `SECURE_CIPHER_THREADS` | Default thread count |
| `--dry-run` | Print actions without writing or deleting |
| `--audit-env` | Print environment analysis report (no VM exit) |
| `SECURE_CIPHER_ALLOW_VM=1` | Allow running inside a VM (lab override) |
| `SECURE_CIPHER_PWHASH` | `interactive` \| `moderate` \| `sensitive` (Argon2 cost) |

## Project layout

```
├── main.cpp                 # Entry point
├── include/secure_cipher/   # Public headers
├── crypto/                  # Encryption, KDF, keystore, I/O
├── cli/                     # Argument parsing
├── platform/                # OS-specific helpers
├── anti_analysis/           # Audit report + VM guard
├── docs/                    # Architecture documentation
├── keys/                    # Local key material (gitignored)
├── data/                    # Sample files for lab exercises
├── NOTICE.md                # Portfolio & use restrictions
└── Makefile
```

## Security notes (lab context)

- This is a **training artifact**, not production ransomware or enterprise-grade crypto tooling.
- Keys live outside encrypted files in `keys/passphrase` — protect that directory like any secret material.
- The VM guard and audit modules demonstrate common attacker/defender techniques; tune overrides only in authorized labs.
- Prefer offline backups and network isolation when running simulations.

## License

Portfolio / educational use only — see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). **Not for redistribution.**
