# HP TouchPad webOS 3.0.5 KeyManager - Reconstructed

This is a complete reconstruction of the `keymanager` service from HP TouchPad webOS 3.0.5, reverse-engineered from the original binary using Ghidra decompilation.

## Overview

The KeyManager service is responsible for secure key management on webOS devices. It provides:

- **Key Generation**: AES symmetric keys and RSA asymmetric key pairs
- **Secure Storage**: SQLite-based encrypted key database
- **Cryptographic Operations**: AES-CBC encryption/decryption, RSA public key encryption
- **File Encryption**: Full file encryption with custom header format
- **Key Export/Import**: Password-protected key wrapping for backup/transfer
- **Backup Integration**: Pre/post backup and restore hooks for webOS backup service
- **Luna Service API**: Full IPC interface for other webOS services

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Luna Service Bus                              │
│                 com.palm.keymanager                              │
├─────────────────────────────────────────────────────────────────┤
│                  KeyServiceHandler                               │
│  (Luna method callbacks: generate, store, fetch, crypt, etc.)   │
├─────────────────────────────────────────────────────────────────┤
│                    CKeyManager                                   │
│         (High-level key management orchestration)                │
├──────────────────┬──────────────────┬───────────────────────────┤
│    CKeyStore     │     CCrypto      │      CFileCrypt           │
│  (SQLite DB)     │  (OpenSSL ops)   │   (File encryption)       │
├──────────────────┼──────────────────┼───────────────────────────┤
│      CKey        │    CPassword     │      CCloudKey            │
│  (Key object)    │ (KDF/key deriv)  │  (Cloud key escrow)       │
└──────────────────┴──────────────────┴───────────────────────────┘
                            │
                      OpenSSL 1.1.1w
```

## Classes

| Class | File | Description |
|-------|------|-------------|
| `CPassword` | cpassword.cpp | PBKDF2-based key derivation from passwords |
| `CKey` | ckey.cpp | Key container with metadata (owner, type, size) |
| `CCrypto` | ccrypto.cpp | OpenSSL wrapper for AES-CBC, RSA, hashing |
| `CKeyStore` | ckeystore.cpp | SQLite database for encrypted key storage |
| `CKeyManager` | ckeymanager.cpp | Main API coordinating all operations |
| `CFileCrypt` | keymanager_misc.cpp | File encryption with Palm header format |
| `CCloudKey` | keymanager_misc.cpp | Palm cloud key escrow client (optional) |
| `KeyServiceHandler` | keyservice_handler.cpp | Luna Service method implementations |
| `KeyServiceApp` | keyservice_handler.cpp | Main application and service registration |

## Building

### Prerequisites

- **ARM Toolchain**: CodeSourcery 2009q1 (`arm-none-linux-gnueabi-g++`)
- **OpenSSL 1.1.1w**: Cross-compiled for ARM
- **ISIS Staging**: webOS SDK staging directory with Luna Service headers
- **webOS rootfs**: Original TouchPad rootfs for linking against Luna libraries

### Configuration

Edit the `Makefile` to set paths:

```makefile
TOOLCHAIN = /path/to/arm-2009q1
OPENSSL_DIR = /path/to/openssl-1.1.1w
ISIS_STAGING = /path/to/isis-project/staging/armv7
ROOTFS_LIB = /path/to/untouched-rootfs/usr/lib
```

### Build Targets

```bash
# Build core tests (no SQLite required)
make all

# Build full test suite (requires SQLite)
make full

# Build Luna service executable
make service

# Run tests
make test       # Core tests only
make test-full  # Full test suite

# Clean
make clean
```

## Luna Service API

Service name: `com.palm.keymanager`

### Private Methods (/)

| Method | Description |
|--------|-------------|
| `generate` | Generate new AES or RSA key |
| `store` | Store key data in keystore |
| `fetch` | Retrieve key by name and owner |
| `remove` | Delete key from keystore |
| `crypt` | Encrypt or decrypt data |
| `fileEncrypt` | Encrypt a file |
| `fileDecrypt` | Decrypt a file |
| `export` | Export key wrapped with password |
| `import` | Import password-wrapped key |
| `keyInfo` | Get key metadata |
| `hash` | Compute SHA hash of data |
| `hmac` | Compute HMAC of data |
| `rsaEncrypt` | RSA public key encryption |
| `rsaDecrypt` | RSA private key decryption |

### Backup Methods

| Method | Description |
|--------|-------------|
| `preBackup` | Prepare for backup (exports keys) |
| `postBackup` | Cleanup after backup |
| `preRestore` | Prepare for restore |
| `postRestore` | Apply restored keys |

### Example Usage

```json
// Generate AES-256 key
{
    "keyname": "mykey",
    "owner": "com.example.app",
    "type": "AES",
    "size": 256
}

// Encrypt data
{
    "keyname": "mykey",
    "owner": "com.example.app",
    "decrypt": false,
    "data": "base64-encoded-plaintext"
}
```

## Cryptographic Details

### Key Derivation (CPassword)

- **Algorithm**: PBKDF2-HMAC-SHA1
- **Iterations**: 4096 (configurable)
- **Salt**: Random 16 bytes
- **Output**: 256-bit key

### Symmetric Encryption (CCrypto)

- **Algorithm**: AES-256-CBC
- **IV**: Random 16 bytes, prepended to ciphertext
- **Padding**: PKCS#7

### Asymmetric Encryption (CCrypto)

- **Algorithm**: RSA with OAEP padding
- **Default key size**: 2048 bits

### File Encryption Format

```
┌──────────────────────────────────┐
│ Magic: "KEPS" (4 bytes)          │
│ Version: 1 (4 bytes)             │
│ Key name length (4 bytes)        │
│ Key name (variable)              │
│ Owner length (4 bytes)           │
│ Owner (variable)                 │
│ Key type (4 bytes)               │
│ Key size (4 bytes)               │
│ Encrypted key blob length        │
│ Encrypted key blob               │
│ IV (16 bytes)                    │
│ Encrypted file data              │
└──────────────────────────────────┘
```

## Database Schema

Keys are stored in SQLite with the following schema:

```sql
CREATE TABLE keys (
    id INTEGER PRIMARY KEY,
    keyname TEXT NOT NULL,
    owner TEXT NOT NULL,
    keytype INTEGER NOT NULL,
    keysize INTEGER NOT NULL,
    keydata BLOB NOT NULL,
    created INTEGER NOT NULL,
    UNIQUE(keyname, owner)
);
```

## Cloud Key Escrow (CCloudKey)

The original Palm cloud key escrow service is defunct. The implementation preserves the original protocol for compatibility with potential replacement servers.

**Original Server**: `http://brm.qa.palmws.com/keyescrow/`

**Protocol**:
- POST request with JSON body containing device ID and public key
- Server responds with encrypted key bytes
- Build with `-DHAVE_CURL` to enable (requires libcurl)

## Deployment

1. Build with `make service`
2. Copy `keymanager` binary to `/usr/bin/` on device
3. Ensure OpenSSL 1.1.1w libraries are in `/usr/lib/`
4. Service file should register with Luna Service bus

## Testing

```bash
# Run KDF tests
./test_kdf

# Run crypto tests (AES, RSA)
./test_crypto

# Run full integration tests (requires SQLite)
./test_keymanager
```

## Original Binary Analysis

The reconstruction was based on Ghidra decompilation of:
- **Binary**: `/usr/bin/keymanager` from webOS 3.0.5
- **Size**: ~180KB (original)
- **Symbols**: Stripped, but C++ mangled names recoverable

Key functions were identified at these addresses:
- `CPassword::generatePasswordKey`: 0x0000c9a0
- `CCrypto::encrypt`: 0x0000a404
- `CKeyStore::insertKey`: 0x0000d6e0
- `CKeyManager::generateKey`: 0x0000b534
- `KeyServiceHandler::cbGenerate`: 0x000138bc

## License

This is a reconstruction for preservation and educational purposes. The original keymanager was proprietary HP/Palm software.

## Authors

Reconstructed by reverse engineering the original HP TouchPad webOS 3.0.5 binary.
