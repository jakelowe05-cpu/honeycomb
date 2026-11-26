# Honeycomb

**Your data. Your devices. Your people.**

Honeycomb is intended to become free, open-source, local-first software for encrypted backup, synchronization, and sharing across a person's own devices and trusted peers.

## Prototype 0.3

This Windows desktop prototype provides:
- Local file encryption and restoration using Argon2id and XChaCha20-Poly1305.
- Direct one-file transfer of an already-encrypted `.hny` file between computers on a local network.
- The transfer sends ciphertext only; the sender's passphrase is not transmitted.
- The receiver chooses the destination path, and existing files are never overwritten.
- Automated tests for local encryption, wrong-passphrase rejection, and encrypted-container validation.

## First LAN transfer test

1. Run Honeycomb on both Windows computers connected to the same private network.
2. On the receiving computer, choose a destination filename under **Save received file as**, leave **Listen on** as `0.0.0.0:45820`, then click **WAIT FOR ONE FILE**.
3. If Windows Firewall asks, allow Honeycomb on the **Private network only**.
4. Find the receiving computer's local IPv4 address (for example, `192.168.1.25`). On the sending computer, choose the `.hny` file, enter that address followed by `:45820` (for example, `192.168.1.25:45820`), then click **SEND ENCRYPTED FILE**.
5. The received `.hny` file can be restored on the receiving computer using the same passphrase used to encrypt it.

This is a one-shot transfer, not automatic backup or device pairing. The receiver accepts one incoming connection. The listener is not authenticated, so use this only on a trusted private LAN and stop listening after the transfer. Do not expose the port to the public internet.

## Important limitations

This is an early prototype, not a complete backup system. It has no automatic folder backup, version history, persistent device pairing, multi-peer replication, or internet-wide NAT traversal yet. Files are read into memory and the local encryption limit is 512 MiB. The transfer is not independently security-audited. Keep separate backups of important data and do not use Honeycomb as your only copy.
