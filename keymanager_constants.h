/*
 * Keymanager Constants
 * Reconstructed from Ghidra decompilation
 */

#ifndef KEYMANAGER_CONSTANTS_H
#define KEYMANAGER_CONSTANTS_H

namespace LunaKeyMgmt {

// Key Algorithm Types (from CKey::keyTypeName @ 0x0001de08)
enum KeyAlgorithm {
    KEY_ALG_NONE        = 1,
    KEY_ALG_AES         = 2,
    KEY_ALG_RSA         = 3,
    KEY_ALG_BF          = 4,   // Blowfish
    KEY_ALG_3DES        = 5,
    KEY_ALG_SHA1        = 6,
    KEY_ALG_MD5         = 7,
    KEY_ALG_RSA_SHA1    = 8,
    KEY_ALG_HMAC_SHA1   = 9,
    KEY_ALG_BLOB        = 10,
    KEY_ALG_ASCIIBLOB   = 11,
    KEY_ALG_DES         = 12
};

// Cipher Modes (from CKeyManager::stringToMode @ 0x000173d0)
enum CipherMode {
    MODE_NONE   = 0,
    MODE_ECB    = 10,
    MODE_CBC    = 20,
    MODE_CFB    = 30,
    MODE_OFB    = 40
};

// Padding Modes (from CKeyManager::stringToPad @ 0x00017444)
enum PaddingMode {
    PAD_NONE    = 0,
    PAD_PKCS5   = 1,
    PAD_PKCS7   = 2,
    PAD_ZERO    = 3
};

// Encryption Operation
enum CryptOperation {
    CRYPT_ENCRYPT = 1,
    CRYPT_DECRYPT = 0
};

// Key Type (public/private for RSA)
enum KeyType {
    KEY_TYPE_SECRET  = 0,
    KEY_TYPE_PUBLIC  = 1,
    KEY_TYPE_PRIVATE = 2
};

// Block sizes (from CKey::blocksize @ 0x0001dee4)
const int AES_BLOCK_SIZE = 16;
const int MD5_BLOCK_SIZE = 16;
const int DES_BLOCK_SIZE = 8;
const int BF_BLOCK_SIZE = 8;
const int TRIPLE_DES_BLOCK_SIZE = 8;
const int SHA1_BLOCK_SIZE = 20;
const int HMAC_SHA1_SIZE = 20;

// KDF Parameters (from CPassword::genKeyAndIVFromPassword @ 0x00020794)
const int KDF_ITERATIONS = 0x400;  // 1024
const int DEVICE_ID_LENGTH = 28;   // 0x1c bytes

// Database path
const char* const DEFAULT_DB_PATH = "/var/palm/data/keys.db";

} // namespace LunaKeyMgmt

#endif /* KEYMANAGER_CONSTANTS_H */
