/*
 * CPassword Implementation
 * Reconstructed from Ghidra decompilation of keymanager binary
 *
 * Original function: LunaKeyMgmt::CPassword::genKeyAndIVFromPassword @ 0x00020794
 */

#include "keymanager_types.h"
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

namespace LunaKeyMgmt {

// Static instance for PinnedMemory singleton
PinnedMemory* PinnedMemory::m_pInstance = NULL;

// Device ID file lists (from .data section @ 0x43628, 0x43630)
static const char* devices[] = { "nduid", NULL };
static const char* tokens[] = { "ProdSN", "HWoRev", "ProductSKU", NULL };

//-----------------------------------------------------------------------------
// PinnedMemory Implementation
//-----------------------------------------------------------------------------

PinnedMemory::PinnedMemory() : m_memory(NULL), m_size(0) {
}

PinnedMemory::~PinnedMemory() {
}

PinnedMemory* PinnedMemory::Instance() {
    if (m_pInstance == NULL) {
        m_pInstance = new PinnedMemory();
    }
    return m_pInstance;
}

void* PinnedMemory::malloc(size_t size) {
    // In the original, this uses mlock() to prevent swapping
    // For now, just use regular malloc
    void* ptr = ::malloc(size);
    if (ptr) {
        // mlock(ptr, size);  // Would pin memory in real implementation
    }
    return ptr;
}

void PinnedMemory::free(void* ptr) {
    // In the original, this uses munlock() before freeing
    if (ptr) {
        // munlock(ptr, size);  // Would unpin memory in real implementation
        ::free(ptr);
    }
}

//-----------------------------------------------------------------------------
// DeviceID Implementation
//-----------------------------------------------------------------------------

DeviceID::DeviceID() : initialized(false), md_ctx(NULL) {
    memset(device_id_string, 0, sizeof(device_id_string));
}

DeviceID::~DeviceID() {
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
    }
}

void DeviceID::setup() {
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx) {
        EVP_DigestInit(md_ctx, EVP_sha1());
    }
}

void DeviceID::input(const uchar* data, int len) {
    if (md_ctx && data && len > 0) {
        EVP_DigestUpdate(md_ctx, data, len);
    }
}

int DeviceID::readfile(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    char buffer[256];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        input((const uchar*)buffer, bytes_read);
    }

    return bytes_read;
}

int DeviceID::readfiles(const char* basepath, const char** files) {
    int count = 0;
    char fullpath[512];

    for (int i = 0; files[i] != NULL; i++) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", basepath, files[i]);
        if (readfile(fullpath) >= 0) {
            count++;
        }
    }

    return count;
}

void DeviceID::final() {
    if (md_ctx) {
        uchar hash[EVP_MAX_MD_SIZE];
        uint hash_len = 0;

        EVP_DigestFinal(md_ctx, hash, &hash_len);

        // Convert to hex string (first 14 bytes = 28 hex chars)
        for (int i = 0; i < 14 && i < (int)hash_len; i++) {
            sprintf(&device_id_string[i * 2], "%02x", hash[i]);
        }
        device_id_string[28] = '\0';
    }
}

char* DeviceID::get() {
    /*
     * Original @ 0x00027660:
     *
     * if (this->initialized == 0) {
     *     setup(this);
     *     input(this, "\\\\...66666666666666666666", 0x14);
     *     readfiles(this, "/proc", devices);
     *     readfiles(this, "/dev/tokens", tokens);
     *     input(this, "66666666666666666666", 0x14);
     *     final(this);
     * }
     * return this->device_id_string;
     */

    if (!initialized) {
        setup();

        // Padding prefix (from decompilation)
        const char* prefix = "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\66666666666666666666";
        input((const uchar*)prefix, 0x14);

        // Read device identifiers
        readfiles("/proc", devices);        // Reads /proc/nduid
        readfiles("/dev/tokens", tokens);   // Reads ProdSN, HWoRev, ProductSKU

        // Padding suffix
        const char* suffix = "66666666666666666666";
        input((const uchar*)suffix, 0x14);

        final();
        initialized = true;
    }

    return device_id_string;
}

//-----------------------------------------------------------------------------
// CPassword Implementation
//-----------------------------------------------------------------------------

CPassword::CPassword() : key(NULL), iv(NULL), key_length(0), iv_length(0) {
}

CPassword::CPassword(const char* password, const char* salt) {
    key = NULL;
    iv = NULL;
    key_length = 0;
    iv_length = 0;
    genKeyAndIVFromPassword(password, salt, true);
}

CPassword::CPassword(const char* password, const char* salt, bool append_device_id) {
    key = NULL;
    iv = NULL;
    key_length = 0;
    iv_length = 0;
    genKeyAndIVFromPassword(password, salt, append_device_id);
}

CPassword::~CPassword() {
    if (key) {
        OPENSSL_cleanse(key, key_length);
        PinnedMemory::Instance()->free(key);
        key = NULL;
    }
    if (iv) {
        OPENSSL_cleanse(iv, iv_length);
        ::free(iv);
        iv = NULL;
    }
}

void CPassword::getKeyAndIv(uchar** out_key, int* out_key_len, uchar** out_iv, int* out_iv_len) {
    if (out_key) *out_key = key;
    if (out_key_len) *out_key_len = key_length;
    if (out_iv) *out_iv = iv;
    if (out_iv_len) *out_iv_len = iv_length;
}

/*
 * Core key derivation function
 * Reconstructed from Ghidra @ 0x00020794
 *
 * Uses PKCS#12 key derivation with:
 * - AES-128-CBC as target cipher
 * - SHA-256 as hash
 * - 1024 iterations
 * - Salt = user_salt || DeviceID (when append_device_id=true)
 */
void CPassword::genKeyAndIVFromPassword(const char* password, const char* salt_input, bool append_device_id) {
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    const EVP_MD* md_type = EVP_sha256();

    DeviceID device_id;

    if (!cipher) {
        throw std::runtime_error("Error allocating cipher CTX");
    }
    if (!md_type) {
        throw std::runtime_error("Error allocating md CTX");
    }

    // Calculate salt length
    size_t salt_len;
    if (password == NULL) {
        salt_len = 0x1c;  // 28 bytes - device ID length
    } else {
        salt_len = strlen(salt_input) + 0x1c;
    }

    // Allocate salt buffer
    uchar* salt = (uchar*)::malloc(salt_len + 1);
    if (!salt) {
        throw std::runtime_error("Error allocating memory");
    }
    salt[salt_len] = '\0';

    // Construct salt
    const char* effective_password = password;

    if (password == NULL) {
        // Use device ID as salt, salt_input as password
        char* device_str = device_id.get();
        strncpy((char*)salt, device_str, 0x1d);
        effective_password = salt_input;
    } else {
        strncpy((char*)salt, salt_input, salt_len);
        if (append_device_id) {
            // Append device ID to salt
            size_t offset = strlen(salt_input);
            char* device_str = device_id.get();
            strncpy((char*)(salt + offset), device_str, 0x1d);
        }
    }

    // Get key and IV lengths from cipher
    key_length = EVP_CIPHER_key_length(cipher);  // 16 for AES-128
    iv_length = EVP_CIPHER_iv_length(cipher);    // 16 for CBC

    // Allocate key in pinned memory (non-swappable)
    PinnedMemory* pinned = PinnedMemory::Instance();
    key = (uchar*)pinned->malloc(key_length);
    if (!key) {
        ::free(salt);
        throw std::runtime_error("Error allocating key memory");
    }

    // Allocate IV in regular memory
    iv = (uchar*)::malloc(iv_length);
    if (!iv) {
        pinned->free(key);
        key = NULL;
        ::free(salt);
        throw std::runtime_error("Error allocating IV memory");
    }

    // Derive key and IV using PKCS#12 KDF
    size_t password_len = effective_password ? strlen(effective_password) : 0;
    size_t salt_len_actual = strlen((char*)salt);

    /*
     * PKCS12_key_gen_asc parameters:
     * - pass: password string (ASCII)
     * - passlen: password length
     * - salt: salt bytes
     * - saltlen: salt length
     * - id: 1 for encryption key, 2 for IV, 3 for MAC key
     * - iter: iteration count (1024 = 0x400)
     * - n: output length
     * - out: output buffer
     * - md_type: hash algorithm
     */

    // Derive encryption key (id=1)
    int result = PKCS12_key_gen_asc(
        effective_password, password_len,
        salt, salt_len_actual,
        1,              // id = 1 for encryption key
        0x400,          // 1024 iterations
        key_length,
        key,
        md_type
    );

    if (result == 0) {
        pinned->free(key);
        key = NULL;
        ::free(salt);
        throw std::runtime_error("Error making key from password");
    }

    // Derive IV (id=2)
    result = PKCS12_key_gen_asc(
        effective_password, password_len,
        salt, salt_len_actual,
        2,              // id = 2 for IV
        0x400,          // 1024 iterations
        iv_length,
        iv,
        md_type
    );

    if (result == 0) {
        pinned->free(key);
        key = NULL;
        ::free(iv);
        iv = NULL;
        ::free(salt);
        throw std::runtime_error("Error making IV from password");
    }

    ::free(salt);
}

} // namespace LunaKeyMgmt
