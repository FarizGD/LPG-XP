# LPG-XP FXPENC v1 binary format

All integers are little-endian except the 32-bit nonce counter embedded in the GCM nonce, which is big-endian.

| Field | Size | Meaning |
|---|---:|---|
| Magic | 8 bytes | ASCII `FXPENC` followed by CR LF |
| Version | 1 byte | `0x01` |
| Chunk size | 4 bytes | Plaintext bytes per chunk |
| Nonce prefix | 8 bytes | Cryptographically random per archive |
| Manifest ciphertext length | 4 bytes | Ciphertext length, excluding its tag |
| Manifest ciphertext | variable | AES-256-GCM encrypted UTF-8 JSON |
| Manifest tag | 16 bytes | Authentication tag |
| File chunks | variable | Ciphertext followed by a 16-byte tag for every chunk |

The manifest has `Version`, `ChunkSize`, and `Entries` fields. Each entry has `Path`, `Length`, and `Chunks`. Entries are ordered by ordinal path. Empty files have zero chunks. Total payload size is the sum of each file's plaintext length plus 16 bytes per chunk.

## Cryptographic rules

- AES-256-GCM, 32-byte key, 12-byte nonce, 16-byte authentication tag.
- Nonce = 8-byte random prefix concatenated with a 4-byte big-endian counter.
- Counter 0 is reserved for the manifest. Content chunks use counters starting at 1 in manifest order.
- Manifest additional authenticated data (AAD) is the version byte followed by the 4-byte little-endian chunk size.
- Chunk AAD is the 4-byte little-endian UTF-8 path length, path bytes, 4-byte little-endian chunk index, 4-byte little-endian chunk length, and 8-byte little-endian total file length.
- Supported chunk sizes are 4 KiB through 16 MiB. The default is 1 MiB.
- The counter must never wrap. The writer rejects a package that exceeds the v1 counter limit.

## Path rules

Archive paths use `/` separators. Absolute paths, drive prefixes, backslashes, empty path components, `.`, `..`, control characters, duplicate paths, and paths longer than 4096 characters are rejected. Extraction verifies the normalized destination remains beneath the requested output directory.

## Versioning

Do not change the binary layout, nonce rules, or AAD semantics without incrementing the format version. FXPENC v1 is the LPG-XP archive format and is not compatible with `.rgssad`.

## Security limitation

The archive key is provided to the game at build time and embedded in its runtime build to avoid a player password prompt. A determined attacker who controls the distributed game can recover that key. FXPENC provides encryption and authenticated tamper detection, not an absolute guarantee that game assets remain secret.
