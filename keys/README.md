# Key directory

This folder holds the **machine key** used to encrypt and decrypt files. It is intentionally not checked into git.

## Generate a key

From the project root, after building:

```bash
make
./secure_cipher keygen ./keys
```

This creates `passphrase` (32-byte hex machine key) with restrictive permissions.

## Use the key

```bash
./secure_cipher -k ./keys encrypt-dir ./data
./secure_cipher -k ./keys decrypt ./data
```

You can also set `SECURE_CIPHER_KEYDIR=./keys` instead of `-k`.

**Do not commit `passphrase` or share it outside authorized lab environments.**
