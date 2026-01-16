/*
 * Miscellaneous Classes Implementation
 * CKeyCache, CCachedKey, CFileCrypt, CWrappedKey, AcctToken, Passcode, CCloudKey
 * Reconstructed from Ghidra decompilation
 */

#include "keymanager_types.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace LunaKeyMgmt {

//-----------------------------------------------------------------------------
// CCachedKey Implementation
//-----------------------------------------------------------------------------

CCachedKey::CCachedKey() : key(NULL), last_access(0), hidden(false) {
}

CCachedKey::CCachedKey(CKey* k) : key(k), hidden(false) {
    last_access = time(NULL);
}

CCachedKey::~CCachedKey() {
    if (key) {
        delete key;
        key = NULL;
    }
}

void CCachedKey::use() {
    last_access = time(NULL);
    hidden = false;
}

void CCachedKey::hide() {
    hidden = true;
}

CKey* CCachedKey::getData(CKey* out_key) {
    if (hidden || !key) {
        return NULL;
    }
    use();
    if (out_key) {
        // Copy to output
        return new CKey(key);
    }
    return key;
}

//-----------------------------------------------------------------------------
// CKeyCache Implementation
//-----------------------------------------------------------------------------

CKeyCache::CKeyCache() {
}

CKeyCache::~CKeyCache() {
    clean();
}

void CKeyCache::add(CKey* key) {
    if (!key) return;

    // Check if already cached
    std::map<ushort, CCachedKey*>::iterator it = cache_by_id.find(key->key_id);
    if (it != cache_by_id.end()) {
        delete it->second;
        cache_by_id.erase(it);
    }

    // Add copy to cache
    cache_by_id[key->key_id] = new CCachedKey(new CKey(key));
}

CKey* CKeyCache::get(ushort key_id) {
    std::map<ushort, CCachedKey*>::iterator it = cache_by_id.find(key_id);
    if (it != cache_by_id.end()) {
        return it->second->getData(NULL);
    }
    return NULL;
}

CKey* CKeyCache::get(const char* owner, const char* name) {
    std::map<ushort, CCachedKey*>::iterator it;
    for (it = cache_by_id.begin(); it != cache_by_id.end(); ++it) {
        CKey* key = it->second->getData(NULL);
        if (key && key->owner && key->name) {
            if (strcmp(key->owner, owner) == 0 && strcmp(key->name, name) == 0) {
                return key;
            }
        }
    }
    return NULL;
}

void CKeyCache::remove(ushort key_id) {
    std::map<ushort, CCachedKey*>::iterator it = cache_by_id.find(key_id);
    if (it != cache_by_id.end()) {
        delete it->second;
        cache_by_id.erase(it);
    }
}

void CKeyCache::clean() {
    std::map<ushort, CCachedKey*>::iterator it;
    for (it = cache_by_id.begin(); it != cache_by_id.end(); ++it) {
        delete it->second;
    }
    cache_by_id.clear();
}

//-----------------------------------------------------------------------------
// CFileCrypt Implementation
//-----------------------------------------------------------------------------

CFileCrypt::CFileCrypt(CKeyStore* store) {
    key_store = store;
    input_file = NULL;
    output_file = NULL;
    buffer = NULL;
    buffer_size = 4096;
    bytes_read = 0;
    encryption_key = NULL;
    iv = NULL;
    iv_length = 0;
}

CFileCrypt::~CFileCrypt() {
    if (input_file) {
        fclose(input_file);
        input_file = NULL;
    }
    if (output_file) {
        fclose(output_file);
        output_file = NULL;
    }
    if (buffer) {
        free(buffer);
        buffer = NULL;
    }
    if (iv) {
        OPENSSL_cleanse(iv, iv_length);
        free(iv);
        iv = NULL;
    }
}

int CFileCrypt::read() {
    if (!input_file || !buffer) return -1;
    bytes_read = fread(buffer, 1, buffer_size, input_file);
    return bytes_read;
}

int CFileCrypt::write() {
    if (!output_file || !buffer) return -1;
    return fwrite(buffer, 1, bytes_read, output_file);
}

int CFileCrypt::encrypt(CKey* key, const char* input_path, const char* output_path) {
    encryption_key = key;

    input_file = fopen(input_path, "rb");
    if (!input_file) {
        throw std::runtime_error("Cannot open input file");
    }

    output_file = fopen(output_path, "wb");
    if (!output_file) {
        fclose(input_file);
        input_file = NULL;
        throw std::runtime_error("Cannot open output file");
    }

    buffer = malloc(buffer_size);
    if (!buffer) {
        throw std::runtime_error("malloc failed");
    }

    // Generate random IV
    iv_length = 16;  // AES block size
    iv = (uchar*)malloc(iv_length);
    RAND_bytes(iv, iv_length);

    // Write header and encrypt
    encodeHeader();
    doEncrypt();

    fclose(input_file);
    fclose(output_file);
    input_file = NULL;
    output_file = NULL;

    return 0;
}

int CFileCrypt::decrypt(const char* input_path, const char* output_path, const char* password) {
    (void)password;  // For key lookup

    input_file = fopen(input_path, "rb");
    if (!input_file) {
        throw std::runtime_error("Cannot open input file");
    }

    output_file = fopen(output_path, "wb");
    if (!output_file) {
        fclose(input_file);
        input_file = NULL;
        throw std::runtime_error("Cannot open output file");
    }

    buffer = malloc(buffer_size);
    if (!buffer) {
        throw std::runtime_error("malloc failed");
    }

    // Read header and decrypt
    decodeHeader();
    doDecrypt();

    fclose(input_file);
    fclose(output_file);
    input_file = NULL;
    output_file = NULL;

    return 0;
}

int CFileCrypt::encodeHeader() {
    // Simple header: "KEYMGR" + version(2) + algorithm(2) + key_id(2) + iv_length(2) + iv
    const char magic[] = "KEYMGR";
    fwrite(magic, 1, 6, output_file);

    uint16_t version = 1;
    fwrite(&version, 2, 1, output_file);

    uint16_t algo = encryption_key ? encryption_key->algorithm : KEY_ALG_AES;
    fwrite(&algo, 2, 1, output_file);

    uint16_t key_id = encryption_key ? encryption_key->key_id : 0;
    fwrite(&key_id, 2, 1, output_file);

    uint16_t ivl = iv_length;
    fwrite(&ivl, 2, 1, output_file);

    fwrite(iv, 1, iv_length, output_file);

    return 0;
}

int CFileCrypt::decodeHeader() {
    char magic[7] = {0};
    fread(magic, 1, 6, input_file);
    if (strcmp(magic, "KEYMGR") != 0) {
        throw std::runtime_error("Invalid file format");
    }

    uint16_t version;
    fread(&version, 2, 1, input_file);

    uint16_t algo;
    fread(&algo, 2, 1, input_file);

    uint16_t key_id;
    fread(&key_id, 2, 1, input_file);

    uint16_t ivl;
    fread(&ivl, 2, 1, input_file);
    iv_length = ivl;

    iv = (uchar*)malloc(iv_length);
    fread(iv, 1, iv_length, input_file);

    // Fetch key from store
    if (key_store) {
        encryption_key = key_store->fetchAndDecryptKey(key_id);
    }

    return 0;
}

int CFileCrypt::doEncrypt() {
    if (!encryption_key) {
        throw std::runtime_error("No encryption key");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), (uchar*)encryption_key->data(), iv);

    uchar* out_buf = (uchar*)malloc(buffer_size + EVP_MAX_BLOCK_LENGTH);

    while ((bytes_read = read()) > 0) {
        int out_len;
        EVP_EncryptUpdate(ctx, out_buf, &out_len, (uchar*)buffer, bytes_read);
        fwrite(out_buf, 1, out_len, output_file);
    }

    int final_len;
    EVP_EncryptFinal(ctx, out_buf, &final_len);
    fwrite(out_buf, 1, final_len, output_file);

    free(out_buf);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int CFileCrypt::doDecrypt() {
    if (!encryption_key) {
        throw std::runtime_error("No encryption key");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), (uchar*)encryption_key->data(), iv);

    uchar* out_buf = (uchar*)malloc(buffer_size + EVP_MAX_BLOCK_LENGTH);

    while ((bytes_read = read()) > 0) {
        int out_len;
        EVP_DecryptUpdate(ctx, out_buf, &out_len, (uchar*)buffer, bytes_read);
        fwrite(out_buf, 1, out_len, output_file);
    }

    int final_len;
    EVP_DecryptFinal(ctx, out_buf, &final_len);
    fwrite(out_buf, 1, final_len, output_file);

    free(out_buf);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

//-----------------------------------------------------------------------------
// CWrappedKey Implementation
//-----------------------------------------------------------------------------

CWrappedKey::CWrappedKey(CKey* key) {
    wrapped_key = new CKey(key);
    encrypted_data = NULL;
    encrypted_length = 0;
    hash = NULL;
    hash_length = 0;
}

CWrappedKey::CWrappedKey(const char* encoded) {
    wrapped_key = NULL;
    encrypted_data = NULL;
    encrypted_length = 0;
    hash = NULL;
    hash_length = 0;
    decode(encoded);
}

CWrappedKey::~CWrappedKey() {
    if (wrapped_key) {
        delete wrapped_key;
        wrapped_key = NULL;
    }
    if (encrypted_data) {
        OPENSSL_cleanse(encrypted_data, encrypted_length);
        free(encrypted_data);
        encrypted_data = NULL;
    }
    if (hash) {
        free(hash);
        hash = NULL;
    }
}

int CWrappedKey::wrap(CKey* wrapping_key) {
    if (!wrapped_key || !wrapping_key) return -1;

    // Generate random IV
    uchar iv[16];
    RAND_bytes(iv, 16);

    encryptKey(wrapping_key, iv, 16);
    hashKey(&hash, &hash_length);

    return 0;
}

int CWrappedKey::unwrap(CKey* wrapping_key) {
    if (!encrypted_data || !wrapping_key) return -1;

    uchar iv[16] = {0};  // TODO: Extract IV from encoded data
    decryptKey(wrapping_key, iv, 16);

    return 0;
}

std::string CWrappedKey::encode() {
    // TODO: Proper encoding with key metadata
    return base64enc(encrypted_data, encrypted_length);
}

int CWrappedKey::decode(const char* encoded) {
    uchar* data = NULL;
    int len = 0;
    base64dec(encoded, &data, &len);

    if (data) {
        encrypted_data = data;
        encrypted_length = len;
    }

    return 0;
}

void CWrappedKey::encryptKey(CKey* wrapping_key, uchar* iv, int iv_len) {
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();

    int data_len = wrapped_key->data_length;
    int out_size = data_len + EVP_CIPHER_block_size(cipher);
    encrypted_data = (uchar*)malloc(out_size);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, cipher, (uchar*)wrapping_key->data(), iv);

    int out_len;
    EVP_EncryptUpdate(ctx, encrypted_data, &out_len, (uchar*)wrapped_key->key_data, data_len);

    int final_len;
    EVP_EncryptFinal(ctx, encrypted_data + out_len, &final_len);

    encrypted_length = out_len + final_len;
    EVP_CIPHER_CTX_free(ctx);

    (void)iv_len;
}

void CWrappedKey::decryptKey(CKey* wrapping_key, uchar* iv, int iv_len) {
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();

    uchar* out = (uchar*)malloc(encrypted_length);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, cipher, (uchar*)wrapping_key->data(), iv);

    int out_len;
    EVP_DecryptUpdate(ctx, out, &out_len, encrypted_data, encrypted_length);

    int final_len;
    EVP_DecryptFinal(ctx, out + out_len, &final_len);

    // Update wrapped key with decrypted data
    if (wrapped_key->key_data) {
        free(wrapped_key->key_data);
    }
    wrapped_key->key_data = out;
    wrapped_key->data_length = out_len + final_len;

    EVP_CIPHER_CTX_free(ctx);

    (void)iv_len;
}

void CWrappedKey::hashKey(uchar** out_hash, int* out_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, encrypted_data, encrypted_length);

    *out_hash = (uchar*)malloc(EVP_MAX_MD_SIZE);
    uint len;
    EVP_DigestFinal(ctx, *out_hash, &len);
    *out_len = len;

    EVP_MD_CTX_free(ctx);
}

//-----------------------------------------------------------------------------
// AcctToken Implementation
//-----------------------------------------------------------------------------

AcctToken::AcctToken() : email(NULL), device_id(NULL), token(NULL), url(NULL) {
}

AcctToken::AcctToken(AcctToken* other) {
    email = other->email ? strdup(other->email) : NULL;
    device_id = other->device_id ? strdup(other->device_id) : NULL;
    token = other->token ? strdup(other->token) : NULL;
    url = other->url ? strdup(other->url) : NULL;
}

AcctToken::~AcctToken() {
    if (email) {
        OPENSSL_cleanse(email, strlen(email));
        free(email);
    }
    if (device_id) {
        free(device_id);
    }
    if (token) {
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
    if (url) {
        free(url);
    }
}

void AcctToken::setDeviceId(const char* id) {
    if (device_id) free(device_id);
    device_id = id ? strdup(id) : NULL;
}

void AcctToken::setUrl(const char* u) {
    if (url) free(url);
    url = u ? strdup(u) : NULL;
}

void AcctToken::setToken(const char* t) {
    if (token) {
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
    token = t ? strdup(t) : NULL;
}

void AcctToken::setEmail(const char* e) {
    if (email) {
        OPENSSL_cleanse(email, strlen(email));
        free(email);
    }
    email = e ? strdup(e) : NULL;
}

//-----------------------------------------------------------------------------
// CCloudKey Implementation - from decompilation @ 0x00023f2c - 0x00024c18
// NOTE: Palm's original servers (brm.qa.palmws.com) are defunct.
// This implementation is preserved for reference and can be adapted
// to use alternative key escrow servers.
//-----------------------------------------------------------------------------

// libcurl is optional - define HAVE_CURL to enable
#ifdef HAVE_CURL
#include <curl/curl.h>
static bool curl_inited = false;
static const char* pCACertFile = "/etc/ssl/certs/ca-certificates.crt";

// Callback for curl to write response data
static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char** response_ptr = (char**)userp;

    char* ptr = (char*)realloc(*response_ptr, realsize + 1);
    if (!ptr) {
        return 0;  // Out of memory
    }

    *response_ptr = ptr;
    memcpy(ptr, contents, realsize);
    ptr[realsize] = '\0';

    return realsize;
}
#endif

CCloudKey::CCloudKey() : response_data(NULL), user_password(NULL), url_prefix(NULL) {
}

CCloudKey::~CCloudKey() {
    if (response_data) {
        free(response_data);
        response_data = NULL;
    }
    if (user_password) {
        OPENSSL_cleanse(user_password, strlen(user_password));
        free(user_password);
        user_password = NULL;
    }
    if (url_prefix) {
        free(url_prefix);
        url_prefix = NULL;
    }
}

int CCloudKey::getKeyBytes(CKey* key, AcctToken* token) {
    // From decompilation @ 0x000241d8
    // Original URL format: http://brm.qa.palmws.com/keyescrow/?email=X&deviceId=Y&token=Z
    // Response contains: "x-palm-key-algorithm: <algo>" header and base64-encoded key body

    if (!key || !token) {
        throw std::runtime_error("Invalid key or token");
    }

    // Check prerequisites
    if (!token->getUrl() || strlen(token->getUrl()) == 0) {
        throw std::runtime_error("waiting on url. Try again.");
    }
    if (!key->data()) {
        throw std::runtime_error("waiting on key data.");
    }
    if (!token->getEmail() || strlen(token->getEmail()) == 0) {
        throw std::runtime_error("waiting on email data. Try again.");
    }
    if (!token->getToken() || strlen(token->getToken()) == 0) {
        throw std::runtime_error("token not available");
    }

#ifdef HAVE_CURL
    // Initialize curl if needed
    if (!curl_inited) {
        curl_global_init(CURL_GLOBAL_ALL);
        curl_inited = true;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize curl");
    }

    // URL-encode parameters
    char* email_enc = curl_easy_escape(curl, token->getEmail(), 0);
    char* device_enc = curl_easy_escape(curl, token->getDeviceId(), 0);
    char* token_enc = curl_easy_escape(curl, token->getToken(), 0);

    // Build request URL
    char url[1024];
    snprintf(url, sizeof(url), "%s/?email=%s&deviceId=%s&token=%s",
             token->getUrl(), email_enc, device_enc, token_enc);

    curl_free(email_enc);
    curl_free(device_enc);
    curl_free(token_enc);

    // Setup curl options
    char* response = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Perform request
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response) {
        if (response) free(response);
        throw std::runtime_error("failed to get response from cloud service");
    }

    // Check for 200 OK
    if (strstr(response, "200 OK") == NULL) {
        char* crlf = strchr(response, '\r');
        if (crlf) *crlf = '\0';
        std::string error = "HTTP error: ";
        error += response;
        free(response);
        throw std::runtime_error(error);
    }

    // Parse x-palm-key-algorithm header
    char* algo_header = strstr(response, "x-palm-key-algorithm: ");
    if (!algo_header) {
        free(response);
        throw std::runtime_error("missing key algorithm header");
    }

    char* algo_value = algo_header + 22;  // Skip "x-palm-key-algorithm: "
    char* algo_end = algo_value;
    while (isalnum(*algo_end)) algo_end++;
    *algo_end = '\0';

    // Verify algorithm matches key type
    const char* key_type = key->keyTypeName();
    if (strncmp(key_type, algo_value, strlen(algo_value)) != 0) {
        free(response);
        throw std::runtime_error("key type mismatch");
    }

    // Find body (after \r\n\r\n)
    char* body = strstr(algo_end + 1, "\r\n\r\n");
    if (!body) {
        free(response);
        throw std::runtime_error("malformed HTTP response: no message body");
    }
    body += 4;  // Skip \r\n\r\n

    // Base64 decode the key data
    uchar* decoded = NULL;
    int decoded_len = 0;
    base64dec(body, &decoded, &decoded_len);

    // Update key data
    if (key->key_data) {
        free(key->key_data);
    }
    key->key_data = malloc(decoded_len);
    if (!key->key_data) {
        free(decoded);
        free(response);
        throw std::runtime_error("malloc failed");
    }
    memcpy(key->key_data, decoded, decoded_len);
    key->data_length = decoded_len;
    key->key_size = decoded_len * 8;
    // Toggle cloud flag (bit 3)
    key->type ^= 8;

    free(decoded);
    free(response);
    curl_global_cleanup();

    return 0;
#else
    // Curl not available - return error
    (void)key;
    (void)token;
    throw std::runtime_error("Cloud key service requires libcurl (define HAVE_CURL to enable)");
#endif
}

const char* CCloudKey::getUserPassword() {
    // From decompilation @ 0x00023f9c
    if (!user_password) {
        user_password = strdup("user");
    }
    return user_password;
}

const char* CCloudKey::getUrlPrefix() {
    // From decompilation @ 0x00023fc8
    // Original Palm QA server (defunct)
    if (!url_prefix) {
        url_prefix = strdup("http://brm.qa.palmws.com/keyescrow/");
    }
    return url_prefix;
}

//-----------------------------------------------------------------------------
// Passcode Implementation
//-----------------------------------------------------------------------------

Passcode::Passcode() : pin(NULL), pin_loaded(false) {
}

Passcode::~Passcode() {
    if (pin) {
        OPENSSL_cleanse(pin, strlen(pin));
        free(pin);
        pin = NULL;
    }
}

int Passcode::readPasscode() {
    // On webOS, this would read from a system file
    // For testing, we'll just return success with no PIN
    pin_loaded = true;
    return 0;
}

bool Passcode::pin_set() {
    return (pin != NULL && strlen(pin) > 0);
}

int Passcode::get_pin(char** out_pin) {
    if (!pin_loaded) {
        readPasscode();
    }
    *out_pin = pin ? strdup(pin) : NULL;
    return pin ? 0 : -1;
}

int Passcode::decryptString(const char* encrypted, const char* salt, char** out_decrypted) {
    return decryptString(encrypted, salt, pin, out_decrypted);
}

int Passcode::decryptString(const char* encrypted, const char* salt, const char* password, char** out_decrypted) {
    // Decrypt using CPassword-derived key
    CPassword pwd(password, salt, true);

    uchar* key = NULL;
    uchar* iv = NULL;
    int key_len = 0, iv_len = 0;
    pwd.getKeyAndIv(&key, &key_len, &iv, &iv_len);

    // Base64 decode the encrypted string
    uchar* enc_data = NULL;
    int enc_len = 0;
    base64dec(encrypted, &enc_data, &enc_len);

    // Decrypt
    uchar* dec_data = (uchar*)malloc(enc_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    int out_len;
    EVP_DecryptUpdate(ctx, dec_data, &out_len, enc_data, enc_len);

    int final_len;
    EVP_DecryptFinal(ctx, dec_data + out_len, &final_len);

    dec_data[out_len + final_len] = '\0';
    *out_decrypted = (char*)dec_data;

    EVP_CIPHER_CTX_free(ctx);
    free(enc_data);

    return 0;
}

//-----------------------------------------------------------------------------
// Utility Functions Implementation
//-----------------------------------------------------------------------------

char* base64enc(const uchar* data, int len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char* result = (char*)malloc(bptr->length + 1);
    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';

    BIO_free_all(b64);
    return result;
}

int base64dec(const char* encoded, uchar** out_data, int* out_len) {
    int enc_len = strlen(encoded);
    *out_data = (uchar*)malloc(enc_len);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded, enc_len);
    mem = BIO_push(b64, mem);

    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(mem, *out_data, enc_len);

    BIO_free_all(mem);
    return 0;
}

char* itoa(int value) {
    char* buf = (char*)malloc(16);
    snprintf(buf, 16, "%d", value);
    return buf;
}

} // namespace LunaKeyMgmt
