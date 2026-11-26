# Honeycomb

**Your data. Your devices. Your people.**

Honeycomb is intended to become free, open-source, local-first software for encrypted backup, synchronization, and sharing across a person's own devices and trusted peers.

## Prototype 0.2

This Windows desktop prototype provides local file encryption and restoration:
- Graphical file picker and encrypt/restore modes.
- Argon2id password-based key derivation.
- XChaCha20-Poly1305 authenticated encryption.
- Fresh random salt and nonce for each encrypted file.
- Refuses to overwrite existing output files.
- Automated tests for successful restore and wrong-passphrase rejection

## Important limitations

This is an early prototype, not a complete backup system. It has no peer-to-peer networking, automatic folder backup, version history, or device pairing yet. It reads files into memory and has a 512 MiB file-size limit. It has not been independently security-audited. Keep separate backups of important data and do not use it as your only copy.
