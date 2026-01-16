/*
 * Keymanager Type Definitions
 * Reconstructed from Ghidra decompilation
 */

#ifndef KEYMANAGER_TYPES_H
#define KEYMANAGER_TYPES_H

#include "ghidra_types.h"
#include "keymanager_constants.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <string>
#include <map>

// Forward declaration for SQLite (actual include in ckeystore.cpp)
struct sqlite3;

namespace LunaKeyMgmt {

// Forward declarations
class CKey;
class CKeyStore;
class CKeyCache;
class CCachedKey;
class CPassword;
class CCrypto;
class CFileCrypt;
class CWrappedKey;
class CCloudKey;
class AcctToken;
class Passcode;
class PinnedMemory;
class DeviceID;

/*
 * PinnedMemory - Secure memory allocation (mlock'd)
 * Singleton pattern - prevents sensitive data from being swapped to disk
 */
class PinnedMemory {
private:
    static PinnedMemory* m_pInstance;
    void* m_memory;
    size_t m_size;

public:
    PinnedMemory();
    ~PinnedMemory();

    static PinnedMemory* Instance();
    void* malloc(size_t size);
    void free(void* ptr);
};

/*
 * DeviceID - Device identification for key binding
 * Hashes hardware tokens to create device-unique identifier
 */
class DeviceID {
private:
    bool initialized;
    char device_id_string[32];
    EVP_MD_CTX* md_ctx;

public:
    DeviceID();
    ~DeviceID();

    void setup();
    void input(const uchar* data, int len);
    void final();
    int readfile(const char* path);
    int readfiles(const char* basepath, const char** files);
    char* get();
};

/*
 * CPassword - Password-based key derivation
 * Uses PKCS#12 KDF with SHA-256 and 1024 iterations
 */
class CPassword {
public:
    uchar* key;
    uchar* iv;
    int key_length;
    int iv_length;

    CPassword();
    CPassword(const char* password, const char* salt);
    CPassword(const char* password, const char* salt, bool append_device_id);
    ~CPassword();

    void genKeyAndIVFromPassword(const char* password, const char* salt, bool append_device_id);
    void getKeyAndIv(uchar** out_key, int* out_key_len, uchar** out_iv, int* out_iv_len);
};

/*
 * CKey - Key representation
 * Structure layout from decompilation:
 * 0x00: vtable pointer
 * 0x04: ushort key_id
 * 0x08: char* owner
 * 0x0c: char* name
 * 0x10: void* data
 * 0x14: int data_length
 * 0x18: int key_size (bits)
 * 0x1c: ushort algorithm
 * 0x1e: ushort type
 * 0x20: bool encrypted
 * 0x24: void* hash_data
 * 0x28: int hash_length
 */
class CKey {
public:
    ushort key_id;
    char* owner;
    char* name;
    void* key_data;
    int data_length;
    int key_size;        // in bits
    ushort algorithm;    // KeyAlgorithm enum
    ushort type;         // KeyType enum
    bool encrypted;
    void* hash_data;
    int hash_length;

    CKey();
    CKey(const CKey* other);
    CKey(ushort id, const char* owner, const char* name, void* data, int len, ushort algo, ushort type);
    CKey(const char* owner, const char* name, void* data, int len, ushort algo, ushort type);
    CKey(ushort id, const char* owner, const char* name, void* data, int len, int size, ushort algo, ushort type);
    ~CKey();

    void init(ushort id, const char* owner, const char* name, void* data, int len, int size, ushort algo, ushort type);

    void* data();
    int dataLength();
    int keySize();
    int blocksize();
    const char* keyTypeName();
    const char* algorithmName();
    std::string valuesString();

    bool isHash();
    bool isHMAC();
    bool isBlockCipher();
    bool isBlob();
    bool isPublicAlgorithm();

    static const char* algorithmName(ushort algo);
};

/*
 * CCachedKey - Cached key with hide/show functionality
 * Protects key data when not in use
 */
class CCachedKey {
private:
    CKey* key;
    time_t last_access;
    bool hidden;

public:
    CCachedKey();
    CCachedKey(CKey* key);
    ~CCachedKey();

    void use();
    void hide();
    CKey* getData(CKey* out_key);
    time_t getLastAccess() { return last_access; }
};

/*
 * CKeyCache - In-memory key cache
 * Maps key IDs to cached keys
 */
class CKeyCache {
private:
    std::map<ushort, CCachedKey*> cache_by_id;

public:
    CKeyCache();
    ~CKeyCache();

    void add(CKey* key);
    CKey* get(ushort key_id);
    CKey* get(const char* owner, const char* name);
    void remove(ushort key_id);
    void clean();
};

/*
 * CCrypto - OpenSSL crypto operations wrapper
 * Handles symmetric encryption, hashing, HMAC, and RSA
 */
class CCrypto {
private:
    ushort algorithm;
    ushort mode;
    ushort padding;
    ushort operation;   // encrypt or decrypt
    CKey* key;
    EVP_CIPHER_CTX* cipher_ctx;
    EVP_MD_CTX* md_ctx;
    HMAC_CTX* hmac_ctx;
    RSA* rsa_key;
    bool initialized;
    bool finalized;
    uchar* iv;
    int iv_length;

public:
    CCrypto(ushort algorithm);
    CCrypto(CKey* key, ushort mode, ushort pad, ushort operation, void* iv, int iv_len, ushort key_type);
    ~CCrypto();

    // Algorithm info
    bool isHash();
    bool isHMAC();
    bool isBlockCipher();
    bool isPublicAlgorithm();
    bool isModeValid();
    bool isPadValid();
    bool isAlgorithmValid();
    bool isEncValid();

    // Key size validation
    bool verifyBlockCipherSize(uint size);
    bool verifyPublicAlgorithmKeySize(uint size);

    // OpenSSL object getters
    const EVP_CIPHER* getOpensslCipher();
    const EVP_MD* getOpensslMD();

    // Key generation
    static CKey* generateKey(const char* owner, const char* name, ushort algo, ushort type, uint key_bits);

    // Cipher operations
    int cipherUpdate(void* in, int in_len, void* out, int* out_len);
    int cipherFinal(void* out, int* out_len);

    // RSA operations
    int rsaPublicEncrypt(void* in, int in_len, void* out, int* out_len);
    int rsaPrivateDecrypt(void* in, int in_len, void* out, int* out_len);
    int rsaPrivateEncrypt(void* in, int in_len, void* out, int* out_len);
    int rsaPublicDecrypt(void* in, int in_len, void* out, int* out_len);
    int rsaSize();
    static CKey* extractPublicKey(CKey* private_key);

    // Static hash/HMAC functions
    static int hash(ushort algo, void* in, int in_len, void* out, int* out_len);
    static int hmac(ushort algo, void* key_data, int key_len, void* in, int in_len, void* out, int* out_len);
};

/*
 * CKeyStore - SQLite-based key storage
 * Manages encrypted key database
 */
class CKeyStore {
private:
    sqlite3* db;
    uchar* master_key;
    int master_key_length;
    uchar* master_iv;
    int master_iv_length;
    bool is_unlocked;
    CKeyCache* cache;
    char* stored_password;
    AcctToken* acct_token;
    std::string db_path;

public:
    CKeyStore();
    ~CKeyStore();

    // Database operations
    int connect();
    void close();
    int create(const char* password, const char* salt, bool use_device_id);
    int open(const char* dbpath, const char* password);
    int open(const char* dbpath, const char* password, const char* salt);
    int open(const char* dbpath, const char* password, const char* salt, bool create_if_missing);
    int open(const char* dbpath, const char* password, const char* salt, bool create_if_missing, bool use_device_id);
    void destroy();
    int prep();
    int checkTable();

    // Key operations
    int insertKey(CKey* key);
    int deleteKey(ushort key_id);
    CKey* fetchEncryptedKey(ushort key_id);
    CKey* fetchAndDecryptKey(ushort key_id);
    CKey* fetchKeyInfo(ushort key_id);
    int listKeys(const char* owner);
    int searchKey(const char* owner, const char* name);

    // Encryption
    void encryptKey(CKey* key);
    void encryptKey(CKey* key, uchar* wrap_key, int wrap_key_len, uchar* iv, int iv_len);
    void decryptKey(CKey* key);
    void decryptKey(CKey* key, uchar* wrap_key, int wrap_key_len, uchar* iv, int iv_len);
    void hashKey(CKey* key, uchar** out_hash, int* out_len);

    // Master key
    void storeMasterKey(const char* password, const char* salt, bool create_new, bool use_device_id);
    void createAndStoreMasterKey(const char* password, const char* salt, bool use_device_id);
    bool masterKeyPresent();
    int unlock(const char* password, const char* salt, bool use_device_id);
    void lock();
    bool unlocked();

    // Password change
    int changePassword(const char* old_pass, const char* new_pass, const char* salt, const char* new_salt);

    // Backup/restore
    int backup(const char* path, const char* password, const char* salt);
    int restore(const char* path, const char* password, const char* salt);
    int restore(const char* path, const char* password, const char* salt, bool overwrite);

    // Wrapped key export/import
    char* exportWrappedKey(ushort key_id, ushort wrap_key_id);
    int importWrappedKey(const char* wrapped);

    // Cloud
    int cloudGetKeyBytes(CKey* key);

    // Cache
    void addToCache(CKey* key);
    CKey* getFromCache(ushort key_id);
    CKey* getFromCache(const char* owner, const char* name);
    void removeFromCache(ushort key_id);

    // Token
    AcctToken* getAcctToken();
    void setAcctToken(AcctToken* token);
};

/*
 * CFileCrypt - File encryption/decryption
 * Encrypts files with header containing key info
 */
class CFileCrypt {
private:
    CKeyStore* key_store;
    FILE* input_file;
    FILE* output_file;
    void* buffer;
    size_t buffer_size;
    size_t bytes_read;
    CKey* encryption_key;
    uchar* iv;
    int iv_length;

public:
    CFileCrypt(CKeyStore* store);
    ~CFileCrypt();

    int encrypt(CKey* key, const char* input_path, const char* output_path);
    int decrypt(const char* input_path, const char* output_path, const char* password);

private:
    int read();
    int write();
    int encodeHeader();
    int decodeHeader();
    int doEncrypt();
    int doDecrypt();
};

/*
 * CWrappedKey - Key wrapping for secure export/import
 * Encrypts key data with another key for transport
 */
class CWrappedKey {
private:
    CKey* wrapped_key;
    uchar* encrypted_data;
    int encrypted_length;
    uchar* hash;
    int hash_length;
    std::string encoded_string;

public:
    CWrappedKey(CKey* key);
    CWrappedKey(const char* encoded);
    ~CWrappedKey();

    int wrap(CKey* wrapping_key);
    int unwrap(CKey* wrapping_key);
    std::string encode();
    int decode(const char* encoded);

    void encryptKey(CKey* wrapping_key, uchar* iv, int iv_len);
    void decryptKey(CKey* wrapping_key, uchar* iv, int iv_len);
    void hashKey(uchar** out_hash, int* out_len);

    CKey* getKey() { return wrapped_key; }
};

/*
 * AcctToken - Account token for cloud key escrow
 */
class AcctToken {
private:
    char* email;
    char* device_id;
    char* token;
    char* url;

public:
    AcctToken();
    AcctToken(AcctToken* other);
    ~AcctToken();

    void setDeviceId(const char* id);
    void setUrl(const char* url);
    void setToken(const char* token);
    void setEmail(const char* email);

    const char* getDeviceId() { return device_id; }
    const char* getUrl() { return url; }
    const char* getToken() { return token; }
    const char* getEmail() { return email; }
};

/*
 * CCloudKey - Cloud key escrow retrieval
 * Fetches keys from Palm's cloud service (defunct)
 */
class CCloudKey {
private:
    void* response_data;
    char* user_password;
    char* url_prefix;

public:
    CCloudKey();
    ~CCloudKey();

    int getKeyBytes(CKey* key, AcctToken* token);
    const char* getUserPassword();
    const char* getUrlPrefix();
};

/*
 * Passcode - Device PIN/passcode management
 */
class Passcode {
private:
    char* pin;
    bool pin_loaded;

public:
    Passcode();
    ~Passcode();

    int readPasscode();
    bool pin_set();
    int get_pin(char** out_pin);
    int decryptString(const char* encrypted, const char* salt, char** out_decrypted);
    int decryptString(const char* encrypted, const char* salt, const char* password, char** out_decrypted);
};

/*
 * CKeyManager - Main API class for key management
 * Wraps CKeyStore and provides high-level operations
 * From decompilation @ 0x00017238 - 0x00019b9c
 */
class CKeyManager {
private:
    CKeyStore* key_store;
    bool initialized;
    CCrypto* crypto_context;

public:
    CKeyManager();
    ~CKeyManager();

    // Initialization
    int initialize(const char* dbpath, const char* password, const char* salt);
    int initialize(const char* dbpath, const char* password, const char* salt, bool use_device_id);
    void finish();

    // Key generation and storage
    CKey* generateKey(const char* owner, const char* name, int key_bits, ushort algo, ushort type);
    int storeKey(const char* owner, const char* name, void* data, int len, ushort algo, ushort type);

    // Key retrieval
    CKey* fetchKey(ushort key_id);
    CKey* fetchKey(const char* owner, const char* name);
    int fetchKeyId(const char* owner, const char* name);

    // Key removal
    int removeKey(ushort key_id);
    int removeKey(const char* owner, const char* name);

    // Key information
    CKey* keyInfo(ushort key_id);
    CKey* keyInfo(const char* owner, const char* name);
    ushort keyAlgorithm(ushort key_id);
    int blocksize(ushort key_id);

    // Encryption/decryption (one-shot)
    int crypt(ushort key_id, ushort mode, ushort pad, ushort op,
              void* iv, int iv_len, void* in, int in_len, void* out, int* out_len);

    // Encryption/decryption (streaming)
    int cryptInit(ushort key_id, ushort mode, ushort pad, ushort op, void* iv, int iv_len);
    int cryptUpdate(void* in, int in_len, void* out, int* out_len);
    int cryptFinal(void* out, int* out_len);

    // File encryption/decryption
    int fileEncrypt(ushort key_id, const char* input_path, const char* output_path);
    int fileDecrypt(const char* input_path, const char* output_path, const char* password);

    // Key wrapping
    char* exportWrappedKey(ushort key_id, ushort wrap_key_id);
    int importWrappedKey(const char* wrapped);

    // Backup and restore
    int backup(const char* path, const char* password, const char* salt);
    int restore(const char* path, const char* password, const char* salt);

    // Password change
    int changePassword(const char* old_pass, const char* new_pass, const char* salt, const char* new_salt);

    // Hash and HMAC
    static int hash(ushort algo, void* in, int in_len, void* out, int* out_len);
    int hmac(ushort key_id, void* in, int in_len, void* out, int* out_len);

    // RSA operations
    int rsaEncrypt(ushort key_id, void* in, int in_len, void* out, int* out_len);
    int rsaDecrypt(ushort key_id, void* in, int in_len, void* out, int* out_len);

    // String/type conversions
    static const char* typeToString(ushort type);
    static ushort stringToType(const char* str);
    static ushort stringToMode(const char* str);
    static ushort stringToPad(const char* str);
    static const char* algorithmToString(ushort algo);
    static ushort stringToAlgorithm(const char* str);
};

// Utility functions
char* base64enc(const uchar* data, int len);
int base64dec(const char* encoded, uchar** out_data, int* out_len);
char* itoa(int value);

} // namespace LunaKeyMgmt

#endif /* KEYMANAGER_TYPES_H */
