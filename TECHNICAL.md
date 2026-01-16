# KeyManager Technical Documentation

## Class Reference

### LunaKeyMgmt::CPassword

Key derivation from passwords using PBKDF2.

**File**: `cpassword.cpp`

**Ghidra Address**: 0x0000c9a0 - 0x0000d2e0

#### Methods

```cpp
// Generate master key from password using PBKDF2
// password: User password (null-terminated string)
// iterations: PBKDF2 iteration count (default 4096)
// Returns: 0 on success, negative on error
int generatePasswordKey(const char* password, int iterations = 4096);

// Get generated key data
// Returns: Pointer to 32-byte key
unsigned char* getKey();

// Get salt used for key derivation
// Returns: Pointer to 16-byte salt
unsigned char* getSalt();

// Set salt for key derivation (for key recovery)
void setSalt(const unsigned char* salt, int len);

// Clear sensitive data from memory
void clear();
```

#### Constants
- `KDF_ITERATIONS`: 4096 (default)
- `KDF_KEY_SIZE`: 32 bytes (256 bits)
- `KDF_SALT_SIZE`: 16 bytes

---

### LunaKeyMgmt::CKey

Container for cryptographic keys with metadata.

**File**: `ckey.cpp`

**Ghidra Address**: 0x0000a000 - 0x0000a400

#### Enums

```cpp
enum KeyType {
    KEY_NONE = 0,
    KEY_AES = 1,        // Symmetric AES key
    KEY_RSA_PUB = 2,    // RSA public key
    KEY_RSA_PRIV = 3,   // RSA private key
    KEY_RSA_PAIR = 4    // RSA key pair
};
```

#### Methods

```cpp
// Constructor
CKey();

// Set key metadata
void setKeyName(const char* name);
void setOwner(const char* owner);
void setType(KeyType type);
void setSize(int bits);

// Set key data
// data: Key bytes
// len: Length in bytes
void setKeyData(const unsigned char* data, int len);

// Get key properties
const char* getKeyName() const;
const char* getOwner() const;
KeyType getType() const;
int getSize() const;
const unsigned char* getKeyData() const;
int getKeyDataLen() const;

// Serialization
int serialize(unsigned char* buf, int buflen) const;
int deserialize(const unsigned char* buf, int len);
```

---

### LunaKeyMgmt::CCrypto

OpenSSL cryptographic operations wrapper.

**File**: `ccrypto.cpp`

**Ghidra Address**: 0x0000a404 - 0x0000c99c

#### Methods

##### Symmetric Encryption (AES-CBC)

```cpp
// Initialize for encryption/decryption
// key: AES key (16, 24, or 32 bytes)
// keylen: Key length in bytes
// iv: Initialization vector (16 bytes), NULL for random
int init(const unsigned char* key, int keylen, const unsigned char* iv = NULL);

// Encrypt data
// in: Plaintext
// inlen: Plaintext length
// out: Ciphertext buffer (must be inlen + 16 for padding)
// outlen: Output - actual ciphertext length
int encrypt(const void* in, int inlen, void* out, int* outlen);

// Decrypt data
// in: Ciphertext (IV prepended)
// inlen: Ciphertext length
// out: Plaintext buffer
// outlen: Output - actual plaintext length
int decrypt(const void* in, int inlen, void* out, int* outlen);

// Get IV used for encryption
const unsigned char* getIV() const;
```

##### Asymmetric Encryption (RSA)

```cpp
// Generate RSA key pair
// bits: Key size (1024, 2048, 4096)
// pubkey: Output public key in DER format
// publen: Output public key length
// privkey: Output private key in DER format
// privlen: Output private key length
int generateRSAKeyPair(int bits,
                       unsigned char* pubkey, int* publen,
                       unsigned char* privkey, int* privlen);

// RSA public key encryption
// pubkey: Public key in DER format
// publen: Public key length
// in: Plaintext
// inlen: Plaintext length
// out: Ciphertext buffer
// outlen: Output ciphertext length
int rsaPublicEncrypt(const unsigned char* pubkey, int publen,
                     const void* in, int inlen,
                     void* out, int* outlen);

// RSA private key decryption
// privkey: Private key in DER format
// privlen: Private key length
// in: Ciphertext
// inlen: Ciphertext length
// out: Plaintext buffer
// outlen: Output plaintext length
int rsaPrivateDecrypt(const unsigned char* privkey, int privlen,
                      const void* in, int inlen,
                      void* out, int* outlen);
```

##### Hashing

```cpp
// Compute SHA hash
// alg: Algorithm ("sha1", "sha256", "sha384", "sha512")
// data: Input data
// len: Data length
// hash: Output hash buffer
// hashlen: Output hash length
int hash(const char* alg, const void* data, int len,
         unsigned char* hash, int* hashlen);

// Compute HMAC
// alg: Algorithm ("sha1", "sha256")
// key: HMAC key
// keylen: Key length
// data: Input data
// len: Data length
// mac: Output MAC buffer
// maclen: Output MAC length
int hmac(const char* alg, const unsigned char* key, int keylen,
         const void* data, int len,
         unsigned char* mac, int* maclen);
```

---

### LunaKeyMgmt::CKeyStore

SQLite-based encrypted key storage.

**File**: `ckeystore.cpp`

**Ghidra Address**: 0x0000d2e4 - 0x0000e7e8

#### Methods

```cpp
// Open or create keystore database
// path: Database file path
// password: Master password for encryption
// owner: Default owner for operations
// create_new: Create if doesn't exist
// overwrite: Overwrite existing
int open(const char* path, const char* password,
         const char* owner, bool create_new, bool overwrite);

// Close database
void close();

// Insert new key
// key: Key object to store
int insertKey(CKey* key);

// Fetch key by name and owner
// name: Key name
// owner: Key owner
// key: Output key object
int fetchKey(const char* name, const char* owner, CKey* key);

// Remove key
// name: Key name
// owner: Key owner
int removeKey(const char* name, const char* owner);

// List keys for owner
// owner: Key owner
// keys: Output vector of key names
int listKeys(const char* owner, std::vector<std::string>& keys);

// Check if key exists
// name: Key name
// owner: Key owner
// Returns: Key ID if exists, -1 if not
int searchKey(const char* name, const char* owner);

// Backup keystore to file
// path: Backup file path
// password: Backup encryption password
// owner: Owner to backup (NULL for all)
int backup(const char* path, const char* password, const char* owner);

// Restore from backup
// path: Backup file path
// password: Backup decryption password
// owner: Owner to restore (NULL for all)
// merge: Merge with existing keys
int restore(const char* path, const char* password,
            const char* owner, bool merge);

// Change master password
// oldpass: Current password
// newpass: New password
// path: Database path
// owner: Owner
int changePassword(const char* oldpass, const char* newpass,
                   const char* path, const char* owner);
```

#### Database Path
- Default: `/var/palm/data/keys.db`

---

### LunaKeyMgmt::CKeyManager

High-level key management API.

**File**: `ckeymanager.cpp`

**Ghidra Address**: 0x0000b000 - 0x0000c000

#### Methods

```cpp
// Initialize key manager
// dbpath: Database path (NULL for default)
// password: Master password (NULL to defer)
int init(const char* dbpath, const char* password);

// Set/change master password
int setPassword(const char* password);

// Generate new key
// name: Key name
// owner: Key owner
// type: Key type (KEY_AES or KEY_RSA_PAIR)
// bits: Key size in bits
int generateKey(const char* name, const char* owner,
                KeyType type, int bits);

// Store existing key
// key: Key object
int storeKey(CKey* key);

// Fetch key
// name: Key name
// owner: Key owner
// key: Output key object
int fetchKey(const char* name, const char* owner, CKey* key);

// Remove key
// name: Key name
// owner: Key owner
int removeKey(const char* name, const char* owner);

// Encrypt data with stored key
// keyname: Name of key to use
// owner: Key owner
// in: Plaintext
// inlen: Plaintext length
// out: Ciphertext buffer
// outlen: Output ciphertext length
int encrypt(const char* keyname, const char* owner,
            const void* in, int inlen,
            void* out, int* outlen);

// Decrypt data with stored key
// keyname: Name of key to use
// owner: Key owner
// in: Ciphertext
// inlen: Ciphertext length
// out: Plaintext buffer
// outlen: Output plaintext length
int decrypt(const char* keyname, const char* owner,
            const void* in, int inlen,
            void* out, int* outlen);

// Export key wrapped with password
// keyname: Name of key to export
// owner: Key owner
// password: Wrapping password
// out: Output buffer
// outlen: Output length
int exportKey(const char* keyname, const char* owner,
              const char* password,
              unsigned char* out, int* outlen);

// Import wrapped key
// name: Name for imported key
// owner: Key owner
// password: Unwrapping password
// data: Wrapped key data
// len: Data length
int importKey(const char* name, const char* owner,
              const char* password,
              const unsigned char* data, int len);

// Shutdown and cleanup
void shutdown();
```

---

### LunaKeyMgmt::CFileCrypt

File encryption with Palm header format.

**File**: `keymanager_misc.cpp`

**Ghidra Address**: 0x0000e800 - 0x0000f0f4

#### File Format

```
Offset  Size     Description
------  ----     -----------
0       4        Magic "KEPS"
4       4        Version (1)
8       4        Key name length
12      N        Key name
12+N    4        Owner length
16+N    M        Owner
16+N+M  4        Key type
20+N+M  4        Key size (bits)
24+N+M  4        Encrypted key length
28+N+M  K        Encrypted key blob
28+N+M+K 16      IV
44+N+M+K ...     Encrypted file data
```

#### Methods

```cpp
// Encrypt file
// inpath: Input file path
// outpath: Output file path
// keyname: Encryption key name
// owner: Key owner
// km: KeyManager instance
int encryptFile(const char* inpath, const char* outpath,
                const char* keyname, const char* owner,
                CKeyManager* km);

// Decrypt file
// inpath: Input encrypted file path
// outpath: Output decrypted file path
// km: KeyManager instance
int decryptFile(const char* inpath, const char* outpath,
                CKeyManager* km);
```

---

### LunaKeyMgmt::CCloudKey

Palm cloud key escrow client (optional, requires libcurl).

**File**: `keymanager_misc.cpp`

**Ghidra Address**: 0x00010000 - 0x00010400

#### Protocol

```
POST /keyescrow/ HTTP/1.1
Host: brm.qa.palmws.com
Content-Type: application/json

{
    "deviceId": "<device-uuid>",
    "publicKey": "<base64-encoded-public-key>"
}

Response: 200 OK
{
    "keyBytes": "<base64-encoded-encrypted-key>"
}
```

#### Methods

```cpp
// Fetch key from cloud escrow service
// deviceId: Device unique identifier
// publicKey: RSA public key for encryption
// pubKeyLen: Public key length
// keyBytes: Output encrypted key
// keyBytesLen: Output key length
int getKeyBytes(const char* deviceId,
                const unsigned char* publicKey, int pubKeyLen,
                unsigned char* keyBytes, int* keyBytesLen);
```

---

### KeyServiceHandler

Luna Service method handler.

**File**: `keyservice_handler.cpp`

**Ghidra Address**: 0x0000e7ec - 0x00014300

#### Service Registration

```cpp
// Service name
const char* SERVICE_NAME = "com.palm.keymanager";

// Private methods (/)
static LSMethod s_priv_methods[] = {
    { "generate",     cbGenerate,     0 },
    { "store",        cbStore,        0 },
    { "fetch",        cbFetch,        0 },
    { "remove",       cbRemove,       0 },
    { "crypt",        cbCrypt,        0 },
    { "fileEncrypt",  cbFileEncrypt,  0 },
    { "fileDecrypt",  cbFileDecrypt,  0 },
    { "export",       cbExport,       0 },
    { "import",       cbImport,       0 },
    { "keyInfo",      cbKeyInfo,      0 },
    { "hash",         cbHash,         0 },
    { "hmac",         cbHmac,         0 },
    { "rsaEncrypt",   cbRsaEncrypt,   0 },
    { "rsaDecrypt",   cbRsaDecrypt,   0 },
    { "preBackup",    cbPreBackup,    0 },
    { "postBackup",   cbPostBackup,   0 },
    { "preRestore",   cbPreRestore,   0 },
    { "postRestore",  cbPostRestore,  0 },
    { NULL, NULL, 0 }
};

// Public methods (/pub)
static LSMethod s_pub_methods[] = {
    { "hash",         cbHash,         0 },
    { "hmac",         cbHmac,         0 },
    { NULL, NULL, 0 }
};
```

#### JSON Request/Response Format

##### generate

Request:
```json
{
    "keyname": "string",
    "owner": "string",
    "type": "AES|RSA",
    "size": 128|192|256|1024|2048|4096
}
```

Response:
```json
{
    "returnValue": true,
    "keyname": "string"
}
```

##### crypt

Request:
```json
{
    "keyname": "string",
    "owner": "string",
    "decrypt": false,
    "data": "base64-string"
}
```

Response:
```json
{
    "returnValue": true,
    "data": "base64-string"
}
```

##### fetch

Request:
```json
{
    "keyname": "string",
    "owner": "string"
}
```

Response:
```json
{
    "returnValue": true,
    "keyname": "string",
    "owner": "string",
    "type": "AES|RSA_PUB|RSA_PRIV|RSA_PAIR",
    "size": 256,
    "data": "base64-string"
}
```

---

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | SUCCESS | Operation successful |
| -1 | ERR_GENERAL | General error |
| -2 | ERR_INVALID_PARAM | Invalid parameter |
| -3 | ERR_NOT_FOUND | Key not found |
| -4 | ERR_EXISTS | Key already exists |
| -5 | ERR_DB | Database error |
| -6 | ERR_CRYPTO | Cryptographic operation failed |
| -7 | ERR_IO | File I/O error |
| -8 | ERR_MEMORY | Memory allocation failed |
| -9 | ERR_AUTH | Authentication failed |
| -10 | ERR_BACKUP | Backup/restore error |

---

## Security Considerations

1. **Key Storage**: All keys are encrypted with a master password derived key before storage
2. **Memory**: Sensitive data is cleared from memory after use
3. **Random Numbers**: OpenSSL's CSPRNG is used for all random data
4. **Password Validation**: Input strings are checked for invalid characters
5. **Backup Security**: Backup files are encrypted with a separate password

---

## Build Configuration

### Preprocessor Defines

| Define | Description |
|--------|-------------|
| `HAVE_CURL` | Enable cloud key escrow with libcurl |
| `DEBUG` | Enable debug logging |

### Compiler Flags

```makefile
CXXFLAGS = -Wall -Wextra -g -O2
```

### Link Libraries

| Library | Purpose |
|---------|---------|
| libssl | OpenSSL SSL/TLS |
| libcrypto | OpenSSL cryptography |
| libsqlite3 | SQLite database |
| liblunaservice | Luna Service IPC |
| libcjson | JSON parsing |
| libmjson | JSON parsing (alternative) |
| libglib-2.0 | GLib utilities |
| libgthread-2.0 | GLib threading |
| libcurl | HTTP client (optional) |
