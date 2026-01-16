/*
 * CKeyManager Implementation
 * Main API class for key management operations
 * Reconstructed from Ghidra decompilation @ 0x00017238 - 0x00019b9c
 */

#include "keymanager_types.h"
#include <cstring>
#include <cstdlib>
#include <stdexcept>

namespace LunaKeyMgmt {

//-----------------------------------------------------------------------------
// CKeyManager Implementation
//-----------------------------------------------------------------------------

CKeyManager::CKeyManager() {
    key_store = new CKeyStore();
    initialized = false;
    crypto_context = NULL;
}

CKeyManager::~CKeyManager() {
    finish();
    if (key_store) {
        delete key_store;
        key_store = NULL;
    }
}

// From decompilation @ 0x0001767c
int CKeyManager::initialize(const char* dbpath, const char* password, const char* salt) {
    return initialize(dbpath, password, salt, true);
}

int CKeyManager::initialize(const char* dbpath, const char* password, const char* salt, bool use_device_id) {
    if (initialized) {
        return 0;  // Already initialized
    }

    try {
        key_store->open(dbpath, password, salt, true, use_device_id);
        initialized = true;
        return 0;
    } catch (std::exception& e) {
        return -1;
    }
}

// From decompilation @ 0x00017644
void CKeyManager::finish() {
    if (crypto_context) {
        delete crypto_context;
        crypto_context = NULL;
    }
    if (key_store) {
        key_store->close();
    }
    initialized = false;
}

// From decompilation @ 0x000188c0
CKey* CKeyManager::generateKey(const char* owner, const char* name, int key_bits, ushort algo, ushort type) {
    if (!initialized) {
        throw std::runtime_error("KeyManager not initialized");
    }

    CKey* key = CCrypto::generateKey(owner, name, algo, type, key_bits);
    if (key) {
        key_store->insertKey(key);
    }
    return key;
}

// From decompilation @ 0x00018dc0
int CKeyManager::storeKey(const char* owner, const char* name, void* data, int len, ushort algo, ushort type) {
    if (!initialized) {
        return -1;
    }

    CKey* key = new CKey(owner, name, data, len, algo, type);
    key_store->insertKey(key);
    ushort id = key->key_id;
    delete key;
    return id;
}

// From decompilation @ 0x00019868
CKey* CKeyManager::fetchKey(ushort key_id) {
    if (!initialized) {
        return NULL;
    }
    return key_store->fetchAndDecryptKey(key_id);
}

// From decompilation @ 0x00019a8c
CKey* CKeyManager::fetchKey(const char* owner, const char* name) {
    if (!initialized) {
        return NULL;
    }

    int id = key_store->searchKey(owner, name);
    if (id < 0) {
        return NULL;
    }
    return key_store->fetchAndDecryptKey(id);
}

// From decompilation @ 0x000182c8
int CKeyManager::fetchKeyId(const char* owner, const char* name) {
    if (!initialized) {
        return -1;
    }
    return key_store->searchKey(owner, name);
}

// From decompilation @ 0x00017fac
int CKeyManager::removeKey(ushort key_id) {
    if (!initialized) {
        return -1;
    }
    return key_store->deleteKey(key_id);
}

// From decompilation @ 0x000191a4
int CKeyManager::removeKey(const char* owner, const char* name) {
    if (!initialized) {
        return -1;
    }

    int id = key_store->searchKey(owner, name);
    if (id < 0) {
        return -1;
    }
    return key_store->deleteKey(id);
}

// From decompilation @ 0x00017d78
CKey* CKeyManager::keyInfo(ushort key_id) {
    if (!initialized) {
        return NULL;
    }
    return key_store->fetchKeyInfo(key_id);
}

// From decompilation @ 0x000180b0
CKey* CKeyManager::keyInfo(const char* owner, const char* name) {
    if (!initialized) {
        return NULL;
    }

    int id = key_store->searchKey(owner, name);
    if (id < 0) {
        return NULL;
    }
    return key_store->fetchKeyInfo(id);
}

// From decompilation @ 0x00018f3c
ushort CKeyManager::keyAlgorithm(ushort key_id) {
    CKey* info = keyInfo(key_id);
    if (!info) {
        return KEY_ALG_NONE;
    }
    ushort algo = info->algorithm;
    delete info;
    return algo;
}

// From decompilation @ 0x00018548
int CKeyManager::blocksize(ushort key_id) {
    CKey* info = keyInfo(key_id);
    if (!info) {
        return -1;
    }
    int bs = info->blocksize();
    delete info;
    return bs;
}

// From decompilation @ 0x000196b8
int CKeyManager::crypt(ushort key_id, ushort mode, ushort pad, ushort op,
                       void* iv, int iv_len, void* in, int in_len,
                       void* out, int* out_len) {
    CKey* key = fetchKey(key_id);
    if (!key) {
        return -1;
    }

    CCrypto crypto(key, mode, pad, op, iv, iv_len, key->type);

    int update_len = 0;
    int final_len = 0;

    crypto.cipherUpdate(in, in_len, out, &update_len);
    crypto.cipherFinal((uchar*)out + update_len, &final_len);

    *out_len = update_len + final_len;

    delete key;
    return 0;
}

// From decompilation @ 0x00019394
int CKeyManager::cryptInit(ushort key_id, ushort mode, ushort pad, ushort op, void* iv, int iv_len) {
    if (crypto_context) {
        delete crypto_context;
        crypto_context = NULL;
    }

    CKey* key = fetchKey(key_id);
    if (!key) {
        return -1;
    }

    crypto_context = new CCrypto(key, mode, pad, op, iv, iv_len, key->type);
    delete key;
    return 0;
}

// From decompilation @ 0x000183d4
int CKeyManager::cryptUpdate(void* in, int in_len, void* out, int* out_len) {
    if (!crypto_context) {
        return -1;
    }
    return crypto_context->cipherUpdate(in, in_len, out, out_len);
}

// From decompilation @ 0x00018ac0
int CKeyManager::cryptFinal(void* out, int* out_len) {
    if (!crypto_context) {
        return -1;
    }
    int result = crypto_context->cipherFinal(out, out_len);

    delete crypto_context;
    crypto_context = NULL;

    return result;
}

// From decompilation @ 0x000186bc
int CKeyManager::fileEncrypt(ushort key_id, const char* input_path, const char* output_path) {
    CKey* key = fetchKey(key_id);
    if (!key) {
        return -1;
    }

    CFileCrypt fc(key_store);
    int result = fc.encrypt(key, input_path, output_path);
    delete key;
    return result;
}

// From decompilation @ 0x00018c78
int CKeyManager::fileDecrypt(const char* input_path, const char* output_path, const char* password) {
    CFileCrypt fc(key_store);
    return fc.decrypt(input_path, output_path, password);
}

// From decompilation @ 0x00017b70
char* CKeyManager::exportWrappedKey(ushort key_id, ushort wrap_key_id) {
    if (!initialized) {
        return NULL;
    }
    return key_store->exportWrappedKey(key_id, wrap_key_id);
}

// From decompilation @ 0x00017c74
int CKeyManager::importWrappedKey(const char* wrapped) {
    if (!initialized) {
        return -1;
    }
    return key_store->importWrappedKey(wrapped);
}

// From decompilation @ 0x000182c8
int CKeyManager::backup(const char* path, const char* password, const char* salt) {
    if (!initialized) {
        return -1;
    }
    return key_store->backup(path, password, salt);
}

// From decompilation @ 0x00017e7c
int CKeyManager::restore(const char* path, const char* password, const char* salt) {
    if (!initialized) {
        return -1;
    }
    return key_store->restore(path, password, salt);
}

// From decompilation @ 0x00017618
int CKeyManager::changePassword(const char* old_pass, const char* new_pass, const char* salt, const char* new_salt) {
    if (!initialized) {
        return -1;
    }
    return key_store->changePassword(old_pass, new_pass, salt, new_salt);
}

// From decompilation @ 0x00017238
const char* CKeyManager::typeToString(ushort type) {
    switch (type) {
        case KEY_TYPE_SECRET:  return "secret";
        case KEY_TYPE_PUBLIC:  return "public";
        case KEY_TYPE_PRIVATE: return "private";
        default:               return "unknown";
    }
}

// From decompilation @ 0x000174ec
ushort CKeyManager::stringToType(const char* str) {
    if (strcmp(str, "secret") == 0)  return KEY_TYPE_SECRET;
    if (strcmp(str, "public") == 0)  return KEY_TYPE_PUBLIC;
    if (strcmp(str, "private") == 0) return KEY_TYPE_PRIVATE;
    return KEY_TYPE_SECRET;
}

// From decompilation @ 0x000173d0
ushort CKeyManager::stringToMode(const char* str) {
    if (strcmp(str, "ecb") == 0) return MODE_ECB;
    if (strcmp(str, "cbc") == 0) return MODE_CBC;
    if (strcmp(str, "cfb") == 0) return MODE_CFB;
    if (strcmp(str, "ofb") == 0) return MODE_OFB;
    return MODE_CBC;  // Default
}

// From decompilation @ 0x00017444
ushort CKeyManager::stringToPad(const char* str) {
    if (strcmp(str, "none") == 0)  return PAD_NONE;
    if (strcmp(str, "pkcs7") == 0) return PAD_PKCS7;
    if (strcmp(str, "zero") == 0)  return PAD_ZERO;
    return PAD_PKCS7;  // Default
}

// From decompilation @ 0x000175a0
const char* CKeyManager::algorithmToString(ushort algo) {
    return CKey::algorithmName(algo);
}

// From decompilation @ 0x000175c8
ushort CKeyManager::stringToAlgorithm(const char* str) {
    if (strcmp(str, "aes") == 0 || strcmp(str, "AES") == 0)     return KEY_ALG_AES;
    if (strcmp(str, "rsa") == 0 || strcmp(str, "RSA") == 0)     return KEY_ALG_RSA;
    if (strcmp(str, "blowfish") == 0 || strcmp(str, "BF") == 0) return KEY_ALG_BF;
    if (strcmp(str, "3des") == 0 || strcmp(str, "3DES") == 0)   return KEY_ALG_3DES;
    if (strcmp(str, "des") == 0 || strcmp(str, "DES") == 0)     return KEY_ALG_DES;
    if (strcmp(str, "sha1") == 0 || strcmp(str, "SHA1") == 0)   return KEY_ALG_SHA1;
    if (strcmp(str, "md5") == 0 || strcmp(str, "MD5") == 0)     return KEY_ALG_MD5;
    if (strcmp(str, "hmac-sha1") == 0)                          return KEY_ALG_HMAC_SHA1;
    if (strcmp(str, "blob") == 0)                               return KEY_ALG_BLOB;
    return KEY_ALG_NONE;
}

// Hash data
int CKeyManager::hash(ushort algo, void* in, int in_len, void* out, int* out_len) {
    return CCrypto::hash(algo, in, in_len, out, out_len);
}

// HMAC data with key
int CKeyManager::hmac(ushort key_id, void* in, int in_len, void* out, int* out_len) {
    CKey* key = fetchKey(key_id);
    if (!key) {
        return -1;
    }

    int result = CCrypto::hmac(key->algorithm, key->data(), key->dataLength(),
                                in, in_len, out, out_len);
    delete key;
    return result;
}

// RSA encrypt with public key
int CKeyManager::rsaEncrypt(ushort key_id, void* in, int in_len, void* out, int* out_len) {
    CKey* key = fetchKey(key_id);
    if (!key || key->algorithm != KEY_ALG_RSA) {
        if (key) delete key;
        return -1;
    }

    CCrypto crypto(key, MODE_NONE, PAD_NONE, CRYPT_ENCRYPT, NULL, 0, KEY_TYPE_PUBLIC);
    int result = crypto.rsaPublicEncrypt(in, in_len, out, out_len);
    delete key;
    return result;
}

// RSA decrypt with private key
int CKeyManager::rsaDecrypt(ushort key_id, void* in, int in_len, void* out, int* out_len) {
    CKey* key = fetchKey(key_id);
    if (!key || key->algorithm != KEY_ALG_RSA) {
        if (key) delete key;
        return -1;
    }

    CCrypto crypto(key, MODE_NONE, PAD_NONE, CRYPT_DECRYPT, NULL, 0, KEY_TYPE_PRIVATE);
    int result = crypto.rsaPrivateDecrypt(in, in_len, out, out_len);
    delete key;
    return result;
}

} // namespace LunaKeyMgmt
