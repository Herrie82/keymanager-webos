/*
 * CKey Implementation
 * Reconstructed from Ghidra decompilation @ 0x0001dd80 - 0x0001f840
 */

#include "keymanager_types.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>

namespace LunaKeyMgmt {

//-----------------------------------------------------------------------------
// CKey Implementation
//-----------------------------------------------------------------------------

CKey::CKey() {
    key_id = 0xFFFF;
    owner = NULL;
    name = NULL;
    key_data = NULL;
    data_length = 0;
    key_size = 0;
    algorithm = 0;
    type = 0;
    encrypted = false;
    hash_data = NULL;
    hash_length = 0;
}

CKey::CKey(const CKey* other) {
    key_id = other->key_id;
    owner = other->owner ? strdup(other->owner) : NULL;
    name = other->name ? strdup(other->name) : NULL;

    if (other->key_data && other->data_length > 0) {
        key_data = malloc(other->data_length);
        memcpy(key_data, other->key_data, other->data_length);
    } else {
        key_data = NULL;
    }

    data_length = other->data_length;
    key_size = other->key_size;
    algorithm = other->algorithm;
    type = other->type;
    encrypted = other->encrypted;

    if (other->hash_data && other->hash_length > 0) {
        hash_length = other->hash_length;
        hash_data = malloc(hash_length);
        memcpy(hash_data, other->hash_data, hash_length);
    } else {
        hash_data = NULL;
        hash_length = 0;
    }
}

CKey::CKey(ushort id, const char* own, const char* nm, void* dat, int len, ushort algo, ushort tp) {
    init(id, own, nm, dat, len, len * 8, algo, tp);
}

CKey::CKey(const char* own, const char* nm, void* dat, int len, ushort algo, ushort tp) {
    init(0xFFFF, own, nm, dat, len, len * 8, algo, tp);
}

CKey::CKey(ushort id, const char* own, const char* nm, void* dat, int len, int size, ushort algo, ushort tp) {
    init(id, own, nm, dat, len, size, algo, tp);
}

CKey::~CKey() {
    if (key_data) {
        OPENSSL_cleanse(key_data, data_length);
        free(key_data);
        key_data = NULL;
    }
    if (owner) {
        free(owner);
        owner = NULL;
    }
    if (name) {
        free(name);
        name = NULL;
    }
    if (hash_data) {
        free(hash_data);
        hash_data = NULL;
    }
}

void CKey::init(ushort id, const char* own, const char* nm, void* dat, int len, int size, ushort algo, ushort tp) {
    key_id = id;
    owner = own ? strdup(own) : NULL;
    name = nm ? strdup(nm) : NULL;

    if (dat && len > 0) {
        key_data = malloc(len);
        memcpy(key_data, dat, len);
    } else {
        key_data = NULL;
    }

    data_length = len;
    key_size = size;
    algorithm = algo;
    type = tp;
    encrypted = false;
    hash_data = NULL;
    hash_length = 0;
}

void* CKey::data() {
    if (encrypted) {
        return NULL;
    }
    return key_data;
}

int CKey::dataLength() {
    if (encrypted) {
        return 0;
    }
    return data_length;
}

int CKey::keySize() {
    return key_size;
}

// From decompilation @ 0x0001dee4
int CKey::blocksize() {
    switch (algorithm) {
        case KEY_ALG_AES:
        case KEY_ALG_MD5:
            return 16;
        case KEY_ALG_RSA:
            // RSA block size is key size / 8 (rounded up)
            if ((key_size & 7) == 0) {
                return key_size >> 3;
            } else {
                return (key_size >> 3) + 1;
            }
        case KEY_ALG_BF:
        case KEY_ALG_3DES:
        case KEY_ALG_DES:
            return 8;
        case KEY_ALG_SHA1:
        case KEY_ALG_HMAC_SHA1:
            return 20;
        default:
            return 0;
    }
}

// From decompilation @ 0x0001de08
const char* CKey::keyTypeName() {
    switch (algorithm) {
        case KEY_ALG_NONE:      return "none";
        case KEY_ALG_AES:       return "AES";
        case KEY_ALG_RSA:       return "RSA";
        case KEY_ALG_BF:        return "BF";
        case KEY_ALG_3DES:      return "3DES";
        case KEY_ALG_SHA1:      return "SHA1";
        case KEY_ALG_MD5:       return "MD5";
        case KEY_ALG_RSA_SHA1:  return "RSAwithSHA1";
        case KEY_ALG_HMAC_SHA1: return "HMACSHA1";
        case KEY_ALG_BLOB:      return "BLOB";
        case KEY_ALG_ASCIIBLOB: return "ASCIIBLOB";
        case KEY_ALG_DES:       return "DES";
        default:                return NULL;
    }
}

const char* CKey::algorithmName() {
    return keyTypeName();
}

const char* CKey::algorithmName(ushort algo) {
    switch (algo) {
        case KEY_ALG_NONE:      return "none";
        case KEY_ALG_AES:       return "AES";
        case KEY_ALG_RSA:       return "RSA";
        case KEY_ALG_BF:        return "BF";
        case KEY_ALG_3DES:      return "3DES";
        case KEY_ALG_SHA1:      return "SHA1";
        case KEY_ALG_MD5:       return "MD5";
        case KEY_ALG_RSA_SHA1:  return "RSAwithSHA1";
        case KEY_ALG_HMAC_SHA1: return "HMACSHA1";
        case KEY_ALG_BLOB:      return "BLOB";
        case KEY_ALG_ASCIIBLOB: return "ASCIIBLOB";
        case KEY_ALG_DES:       return "DES";
        default:                return NULL;
    }
}

std::string CKey::valuesString() {
    std::ostringstream oss;
    oss << "CKey[id=" << key_id
        << ", owner=" << (owner ? owner : "(null)")
        << ", name=" << (name ? name : "(null)")
        << ", algo=" << algorithmName()
        << ", size=" << key_size
        << ", len=" << data_length
        << ", encrypted=" << (encrypted ? "true" : "false")
        << "]";
    return oss.str();
}

// From decompilation @ 0x0001df8c
bool CKey::isHash() {
    // algorithm 6 (SHA1) or 7 (MD5)
    return (algorithm >= KEY_ALG_SHA1 && algorithm <= KEY_ALG_MD5);
}

// From decompilation @ 0x0001dfa8
bool CKey::isHMAC() {
    return (algorithm == KEY_ALG_HMAC_SHA1);
}

// From decompilation @ 0x0001dfbc
bool CKey::isBlockCipher() {
    return (algorithm == KEY_ALG_AES ||
            algorithm == KEY_ALG_3DES ||
            algorithm == KEY_ALG_DES ||
            algorithm == KEY_ALG_BF);
}

// From decompilation @ 0x0001dfe0
bool CKey::isBlob() {
    return (algorithm == KEY_ALG_BLOB || algorithm == KEY_ALG_ASCIIBLOB);
}

// From decompilation @ 0x0001dffc
bool CKey::isPublicAlgorithm() {
    return (algorithm == KEY_ALG_RSA);
}

} // namespace LunaKeyMgmt
