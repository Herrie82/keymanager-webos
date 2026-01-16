/*
 * CCrypto Implementation
 * Reconstructed from Ghidra decompilation @ 0x00024c20 - 0x00027200
 */

#include "keymanager_types.h"
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace LunaKeyMgmt {

//-----------------------------------------------------------------------------
// CCrypto Implementation
//-----------------------------------------------------------------------------

CCrypto::CCrypto(ushort algo) {
    algorithm = algo;
    mode = MODE_NONE;
    padding = PAD_NONE;
    operation = CRYPT_ENCRYPT;
    key = NULL;
    cipher_ctx = NULL;
    md_ctx = NULL;
    hmac_ctx = NULL;
    rsa_key = NULL;
    initialized = false;
    finalized = false;
    iv = NULL;
    iv_length = 0;
}

CCrypto::CCrypto(CKey* k, ushort m, ushort pad, ushort op, void* init_iv, int init_iv_len, ushort key_type) {
    algorithm = k->algorithm;
    mode = m;
    padding = pad;
    operation = op;
    key = k;
    cipher_ctx = NULL;
    md_ctx = NULL;
    hmac_ctx = NULL;
    rsa_key = NULL;
    initialized = false;
    finalized = false;

    // Copy IV
    if (init_iv && init_iv_len > 0) {
        iv_length = init_iv_len;
        iv = (uchar*)malloc(iv_length);
        memcpy(iv, init_iv, iv_length);
    } else {
        iv = NULL;
        iv_length = 0;
    }

    // Initialize based on algorithm type
    if (isBlockCipher()) {
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (cipher_ctx) {
            const EVP_CIPHER* cipher = getOpensslCipher();
            if (cipher) {
                if (operation == CRYPT_ENCRYPT) {
                    EVP_EncryptInit_ex(cipher_ctx, cipher, NULL,
                                       (const uchar*)k->data(), iv);
                } else {
                    EVP_DecryptInit_ex(cipher_ctx, cipher, NULL,
                                       (const uchar*)k->data(), iv);
                }
                // Set padding
                if (padding == PAD_NONE) {
                    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                }
                initialized = true;
            }
        }
    } else if (isHash()) {
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx) {
            const EVP_MD* md = getOpensslMD();
            if (md) {
                EVP_DigestInit_ex(md_ctx, md, NULL);
                initialized = true;
            }
        }
    } else if (isHMAC()) {
        hmac_ctx = HMAC_CTX_new();
        if (hmac_ctx) {
            const EVP_MD* md = EVP_sha1();  // HMAC-SHA1
            HMAC_Init_ex(hmac_ctx, k->data(), k->dataLength(), md, NULL);
            initialized = true;
        }
    } else if (isPublicAlgorithm()) {
        // RSA - load key from data
        const uchar* key_data = (const uchar*)k->data();
        if (key_type == KEY_TYPE_PRIVATE) {
            rsa_key = d2i_RSAPrivateKey(NULL, &key_data, k->dataLength());
        } else {
            rsa_key = d2i_RSAPublicKey(NULL, &key_data, k->dataLength());
        }
        if (rsa_key) {
            initialized = true;
        }
    }
}

CCrypto::~CCrypto() {
    if (cipher_ctx) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        cipher_ctx = NULL;
    }
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
    }
    if (hmac_ctx) {
        HMAC_CTX_free(hmac_ctx);
        hmac_ctx = NULL;
    }
    if (rsa_key) {
        RSA_free(rsa_key);
        rsa_key = NULL;
    }
    if (iv) {
        OPENSSL_cleanse(iv, iv_length);
        free(iv);
        iv = NULL;
    }
}

// From decompilation @ 0x00024c70
bool CCrypto::isHash() {
    return (algorithm >= KEY_ALG_SHA1 && algorithm <= KEY_ALG_MD5);
}

// From decompilation @ 0x00024c8c
bool CCrypto::isHMAC() {
    return (algorithm == KEY_ALG_HMAC_SHA1);
}

// From decompilation @ 0x00024ca0
bool CCrypto::isBlockCipher() {
    return (algorithm == KEY_ALG_AES ||
            algorithm == KEY_ALG_3DES ||
            algorithm == KEY_ALG_DES ||
            algorithm == KEY_ALG_BF);
}

// From decompilation @ 0x00024cc4
bool CCrypto::isPublicAlgorithm() {
    return (algorithm == KEY_ALG_RSA);
}

// From decompilation @ 0x00024cd8
bool CCrypto::isModeValid() {
    if (!isBlockCipher()) {
        return false;
    }
    // Valid modes are 10-50 (ECB, CBC, CFB, OFB)
    return (mode >= MODE_ECB && mode <= MODE_OFB + 10);
}

// From decompilation @ 0x00024d08
bool CCrypto::isPadValid() {
    if (!isBlockCipher()) {
        return true;  // Padding only matters for block ciphers
    }
    return (padding >= PAD_NONE && padding <= PAD_ZERO);
}

bool CCrypto::isAlgorithmValid() {
    return (algorithm >= KEY_ALG_NONE && algorithm <= KEY_ALG_DES);
}

bool CCrypto::isEncValid() {
    return (operation == CRYPT_ENCRYPT || operation == CRYPT_DECRYPT);
}

bool CCrypto::verifyBlockCipherSize(uint size) {
    switch (algorithm) {
        case KEY_ALG_AES:
            return (size == 128 || size == 192 || size == 256);
        case KEY_ALG_DES:
            return (size == 64);
        case KEY_ALG_3DES:
            return (size == 192);
        case KEY_ALG_BF:
            return (size >= 32 && size <= 448);
        default:
            return false;
    }
}

bool CCrypto::verifyPublicAlgorithmKeySize(uint size) {
    if (algorithm == KEY_ALG_RSA) {
        return (size >= 512 && size <= 4096);
    }
    return false;
}

// From decompilation @ 0x00024fa0
const EVP_CIPHER* CCrypto::getOpensslCipher() {
    switch (algorithm) {
        case KEY_ALG_AES:
            if (key) {
                int key_bits = key->keySize();
                switch (mode) {
                    case MODE_ECB:
                        if (key_bits == 128) return EVP_aes_128_ecb();
                        if (key_bits == 192) return EVP_aes_192_ecb();
                        if (key_bits == 256) return EVP_aes_256_ecb();
                        break;
                    case MODE_CBC:
                        if (key_bits == 128) return EVP_aes_128_cbc();
                        if (key_bits == 192) return EVP_aes_192_cbc();
                        if (key_bits == 256) return EVP_aes_256_cbc();
                        break;
                    case MODE_CFB:
                        if (key_bits == 128) return EVP_aes_128_cfb128();
                        if (key_bits == 192) return EVP_aes_192_cfb128();
                        if (key_bits == 256) return EVP_aes_256_cfb128();
                        break;
                }
            }
            return EVP_aes_128_cbc();  // Default

        case KEY_ALG_DES:
            switch (mode) {
                case MODE_ECB: return EVP_des_ecb();
                case MODE_CBC: return EVP_des_cbc();
                case MODE_CFB: return EVP_des_cfb64();
            }
            return EVP_des_cbc();

        case KEY_ALG_3DES:
            switch (mode) {
                case MODE_ECB: return EVP_des_ede3_ecb();
                case MODE_CBC: return EVP_des_ede3_cbc();
                case MODE_CFB: return EVP_des_ede3_cfb64();
            }
            return EVP_des_ede3_cbc();

        case KEY_ALG_BF:
            switch (mode) {
                case MODE_ECB: return EVP_bf_ecb();
                case MODE_CBC: return EVP_bf_cbc();
                case MODE_CFB: return EVP_bf_cfb64();
            }
            return EVP_bf_cbc();

        default:
            return NULL;
    }
}

// From decompilation @ 0x00025218
const EVP_MD* CCrypto::getOpensslMD() {
    switch (algorithm) {
        case KEY_ALG_SHA1:
        case KEY_ALG_HMAC_SHA1:
            return EVP_sha1();
        case KEY_ALG_MD5:
            return EVP_md5();
        default:
            return NULL;
    }
}

// From decompilation @ 0x00025358
CKey* CCrypto::generateKey(const char* owner, const char* name, ushort algo, ushort type, uint key_bits) {
    int key_bytes = (key_bits + 7) / 8;
    uchar* key_data = NULL;

    if (algo == KEY_ALG_RSA) {
        // Generate RSA key pair
        RSA* rsa = RSA_new();
        BIGNUM* e = BN_new();
        BN_set_word(e, RSA_F4);  // 65537

        if (RSA_generate_key_ex(rsa, key_bits, e, NULL) != 1) {
            BN_free(e);
            RSA_free(rsa);
            throw std::runtime_error("RSA key generation failed");
        }
        BN_free(e);

        // Export private key
        int len = i2d_RSAPrivateKey(rsa, NULL);
        key_data = (uchar*)malloc(len);
        uchar* p = key_data;
        i2d_RSAPrivateKey(rsa, &p);

        RSA_free(rsa);

        CKey* key = new CKey(owner, name, key_data, len, algo, type);
        key->key_size = key_bits;
        free(key_data);
        return key;
    } else {
        // Generate symmetric key
        key_data = (uchar*)malloc(key_bytes);
        if (RAND_bytes(key_data, key_bytes) != 1) {
            free(key_data);
            throw std::runtime_error("Random key generation failed");
        }

        CKey* key = new CKey(owner, name, key_data, key_bytes, algo, type);
        key->key_size = key_bits;
        free(key_data);
        return key;
    }
}

// From decompilation @ 0x00026e94
int CCrypto::cipherUpdate(void* in, int in_len, void* out, int* out_len) {
    if (!initialized || finalized) {
        return -1;
    }

    if (isBlockCipher() && cipher_ctx) {
        if (operation == CRYPT_ENCRYPT) {
            return EVP_EncryptUpdate(cipher_ctx, (uchar*)out, out_len, (const uchar*)in, in_len);
        } else {
            return EVP_DecryptUpdate(cipher_ctx, (uchar*)out, out_len, (const uchar*)in, in_len);
        }
    } else if (isHash() && md_ctx) {
        EVP_DigestUpdate(md_ctx, in, in_len);
        *out_len = 0;
        return 1;
    } else if (isHMAC() && hmac_ctx) {
        HMAC_Update(hmac_ctx, (const uchar*)in, in_len);
        *out_len = 0;
        return 1;
    }

    return -1;
}

// From decompilation @ 0x000269f8
int CCrypto::cipherFinal(void* out, int* out_len) {
    if (!initialized || finalized) {
        return -1;
    }

    finalized = true;

    if (isBlockCipher() && cipher_ctx) {
        int result;
        if (operation == CRYPT_ENCRYPT) {
            result = EVP_EncryptFinal_ex(cipher_ctx, (uchar*)out, out_len);
        } else {
            result = EVP_DecryptFinal_ex(cipher_ctx, (uchar*)out, out_len);
        }
        EVP_CIPHER_CTX_reset(cipher_ctx);
        return result;
    } else if (isHash() && md_ctx) {
        uint len;
        EVP_DigestFinal_ex(md_ctx, (uchar*)out, &len);
        *out_len = len;
        return 1;
    } else if (isHMAC() && hmac_ctx) {
        uint len;
        HMAC_Final(hmac_ctx, (uchar*)out, &len);
        *out_len = len;
        return 1;
    }

    return -1;
}

// RSA public key encryption
// From decompilation @ 0x00026a80
int CCrypto::rsaPublicEncrypt(void* in, int in_len, void* out, int* out_len) {
    if (!initialized || !rsa_key) {
        return -1;
    }

    int rsa_size = RSA_size(rsa_key);
    *out_len = RSA_public_encrypt(in_len, (const uchar*)in, (uchar*)out,
                                   rsa_key, RSA_PKCS1_PADDING);
    return (*out_len > 0) ? 1 : -1;
}

// RSA private key decryption
// From decompilation @ 0x00026b40
int CCrypto::rsaPrivateDecrypt(void* in, int in_len, void* out, int* out_len) {
    if (!initialized || !rsa_key) {
        return -1;
    }

    *out_len = RSA_private_decrypt(in_len, (const uchar*)in, (uchar*)out,
                                    rsa_key, RSA_PKCS1_PADDING);
    return (*out_len > 0) ? 1 : -1;
}

// RSA private key encryption (for signing)
int CCrypto::rsaPrivateEncrypt(void* in, int in_len, void* out, int* out_len) {
    if (!initialized || !rsa_key) {
        return -1;
    }

    *out_len = RSA_private_encrypt(in_len, (const uchar*)in, (uchar*)out,
                                    rsa_key, RSA_PKCS1_PADDING);
    return (*out_len > 0) ? 1 : -1;
}

// RSA public key decryption (for signature verification)
int CCrypto::rsaPublicDecrypt(void* in, int in_len, void* out, int* out_len) {
    if (!initialized || !rsa_key) {
        return -1;
    }

    *out_len = RSA_public_decrypt(in_len, (const uchar*)in, (uchar*)out,
                                   rsa_key, RSA_PKCS1_PADDING);
    return (*out_len > 0) ? 1 : -1;
}

// Get RSA key size
int CCrypto::rsaSize() {
    if (!rsa_key) return 0;
    return RSA_size(rsa_key);
}

// Extract public key from private key
CKey* CCrypto::extractPublicKey(CKey* private_key) {
    if (!private_key || private_key->algorithm != KEY_ALG_RSA) {
        return NULL;
    }

    const uchar* key_data = (const uchar*)private_key->data();
    RSA* rsa = d2i_RSAPrivateKey(NULL, &key_data, private_key->dataLength());
    if (!rsa) {
        return NULL;
    }

    // Export public key only
    int len = i2d_RSAPublicKey(rsa, NULL);
    uchar* pub_data = (uchar*)malloc(len);
    uchar* p = pub_data;
    i2d_RSAPublicKey(rsa, &p);

    RSA_free(rsa);

    CKey* pub_key = new CKey(private_key->owner, private_key->name,
                              pub_data, len, KEY_ALG_RSA, KEY_TYPE_PUBLIC);
    pub_key->key_size = private_key->key_size;
    free(pub_data);

    return pub_key;
}

// Static hash function
int CCrypto::hash(ushort algo, void* in, int in_len, void* out, int* out_len) {
    const EVP_MD* md = NULL;

    switch (algo) {
        case KEY_ALG_SHA1:
            md = EVP_sha1();
            break;
        case KEY_ALG_MD5:
            md = EVP_md5();
            break;
        default:
            // Default to SHA-256
            md = EVP_sha256();
            break;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, in, in_len);

    uint len;
    EVP_DigestFinal_ex(ctx, (uchar*)out, &len);
    *out_len = len;

    EVP_MD_CTX_free(ctx);
    return 1;
}

// Static HMAC function
int CCrypto::hmac(ushort algo, void* key_data, int key_len, void* in, int in_len, void* out, int* out_len) {
    const EVP_MD* md = NULL;

    switch (algo) {
        case KEY_ALG_HMAC_SHA1:
        case KEY_ALG_SHA1:
            md = EVP_sha1();
            break;
        case KEY_ALG_MD5:
            md = EVP_md5();
            break;
        default:
            md = EVP_sha1();
            break;
    }

    uint len;
    HMAC(md, key_data, key_len, (const uchar*)in, in_len, (uchar*)out, &len);
    *out_len = len;

    return 1;
}

} // namespace LunaKeyMgmt
