/*
 * KeyServiceHandler Implementation
 * Luna Service method handlers for keymanager
 * Reconstructed from Ghidra decompilation @ 0x0000e7ec - 0x00014300
 */

#include "keyservice_handler.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <json.h>

using namespace LunaKeyMgmt;

// Singleton instance
KeyServiceHandler* KeyServiceHandler::s_instance = NULL;

// Private method table
LSMethod KeyServiceHandler::s_priv_methods[] = {
    { "generate",    cbGenerate,    (LSMethodFlags)0 },
    { "store",       cbStore,       (LSMethodFlags)0 },
    { "fetch",       cbFetch,       (LSMethodFlags)0 },
    { "remove",      cbRemove,      (LSMethodFlags)0 },
    { "crypt",       cbCrypt,       (LSMethodFlags)0 },
    { "fileEncrypt", cbFileEncrypt, (LSMethodFlags)0 },
    { "fileDecrypt", cbFileDecrypt, (LSMethodFlags)0 },
    { "export",      cbExport,      (LSMethodFlags)0 },
    { "import",      cbImport,      (LSMethodFlags)0 },
    { "keyInfo",     cbKeyInfo,     (LSMethodFlags)0 },
    { "hash",        cbHash,        (LSMethodFlags)0 },
    { "hmac",        cbHmac,        (LSMethodFlags)0 },
    { "rsaEncrypt",  cbRsaEncrypt,  (LSMethodFlags)0 },
    { "rsaDecrypt",  cbRsaDecrypt,  (LSMethodFlags)0 },
    { "preBackup",   cbPreBackup,   (LSMethodFlags)0 },
    { "postBackup",  cbPostBackup,  (LSMethodFlags)0 },
    { "preRestore",  cbPreRestore,  (LSMethodFlags)0 },
    { "postRestore", cbPostRestore, (LSMethodFlags)0 },
    { NULL, NULL, (LSMethodFlags)0 }
};

// Public method table (limited set)
LSMethod KeyServiceHandler::s_pub_methods[] = {
    { "fetch",      cbFetch,      (LSMethodFlags)0 },
    { "crypt",      cbCrypt,      (LSMethodFlags)0 },
    { "hash",       cbHash,       (LSMethodFlags)0 },
    { NULL, NULL, (LSMethodFlags)0 }
};

//-----------------------------------------------------------------------------
// Constructor / Destructor
//-----------------------------------------------------------------------------

KeyServiceHandler::KeyServiceHandler(LSHandle* handle, CKeyManager* km)
    : service_handle(handle), key_manager(km), in_backup(false), in_restore(false)
{
    s_instance = this;
}

KeyServiceHandler::~KeyServiceHandler()
{
    if (s_instance == this) {
        s_instance = NULL;
    }
}

//-----------------------------------------------------------------------------
// Initialization
//-----------------------------------------------------------------------------

int KeyServiceHandler::init()
{
    LSError lserror;
    LSErrorInit(&lserror);

    // Register private methods
    if (!LSRegisterCategory(service_handle, "/", s_priv_methods, NULL, NULL, &lserror)) {
        fprintf(stderr, "Failed to register private methods: %s\n", lserror.message);
        LSErrorFree(&lserror);
        return -1;
    }

    // Register public methods
    if (!LSRegisterCategory(service_handle, "/pub", s_pub_methods, NULL, NULL, &lserror)) {
        fprintf(stderr, "Failed to register public methods: %s\n", lserror.message);
        LSErrorFree(&lserror);
        return -1;
    }

    // Set category data to our handler instance
    LSCategorySetData(service_handle, "/", this, &lserror);
    LSCategorySetData(service_handle, "/pub", this, &lserror);

    return 0;
}

//-----------------------------------------------------------------------------
// Input validation - from decompilation @ 0x0000e7b0
//-----------------------------------------------------------------------------

bool KeyServiceHandler::hasBadChars(const char* str, int len)
{
    if (len < 1) {
        return true;
    }

    for (int i = 0; i < len; i++) {
        char c = str[i];
        // Allow alphanumeric, underscore, hyphen, period
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.')) {
            return true;
        }
    }
    return false;
}

//-----------------------------------------------------------------------------
// Helper functions
//-----------------------------------------------------------------------------

bool KeyServiceHandler::sendError(LSHandle* sh, LSMessage* msg, const char* error_text)
{
    LSError lserror;
    LSErrorInit(&lserror);

    char response[512];
    snprintf(response, sizeof(response),
             "{\"returnValue\":false,\"errorText\":\"%s\"}", error_text);

    bool result = LSMessageReply(sh, msg, response, &lserror);
    if (!result) {
        LSErrorFree(&lserror);
    }
    return result;
}

bool KeyServiceHandler::sendSuccess(LSHandle* sh, LSMessage* msg, const char* payload)
{
    LSError lserror;
    LSErrorInit(&lserror);

    bool result = LSMessageReply(sh, msg, payload, &lserror);
    if (!result) {
        LSErrorFree(&lserror);
    }
    return result;
}

bool KeyServiceHandler::rejectIfInBackup(LSHandle* sh, LSMessage* msg)
{
    if (in_backup) {
        sendError(sh, msg, "Operation not allowed during backup");
        return true;
    }
    return false;
}

char* KeyServiceHandler::getStringParam(const char* payload, const char* key)
{
    if (!payload || !key) return NULL;

    json_t* root = json_parse_document(payload);
    if (!root) return NULL;

    json_t* label = json_find_first_label(root, key);
    if (!label || !label->child) {
        json_free_value(&root);
        return NULL;
    }

    char* result = NULL;
    if (label->child->type == JSON_STRING && label->child->text) {
        result = strdup(label->child->text);
    }

    json_free_value(&root);
    return result;
}

int KeyServiceHandler::getIntParam(const char* payload, const char* key, int default_val)
{
    if (!payload || !key) return default_val;

    json_t* root = json_parse_document(payload);
    if (!root) return default_val;

    json_t* label = json_find_first_label(root, key);
    if (!label || !label->child) {
        json_free_value(&root);
        return default_val;
    }

    int result = default_val;
    if (label->child->type == JSON_NUMBER && label->child->text) {
        result = atoi(label->child->text);
    }

    json_free_value(&root);
    return result;
}

bool KeyServiceHandler::getBoolParam(const char* payload, const char* key, bool default_val)
{
    if (!payload || !key) return default_val;

    json_t* root = json_parse_document(payload);
    if (!root) return default_val;

    json_t* label = json_find_first_label(root, key);
    if (!label || !label->child) {
        json_free_value(&root);
        return default_val;
    }

    bool result = default_val;
    if (label->child->type == JSON_TRUE) {
        result = true;
    } else if (label->child->type == JSON_FALSE) {
        result = false;
    }

    json_free_value(&root);
    return result;
}

//-----------------------------------------------------------------------------
// Generate key - from decompilation @ 0x000138bc
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbGenerate(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    if (self->rejectIfInBackup(sh, msg)) {
        return true;
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* keytype = getStringParam(payload, "keytype");
    int keybits = getIntParam(payload, "size", 128);
    bool nohide = getBoolParam(payload, "nohide", false);
    bool backup = getBoolParam(payload, "backup", false);

    if (!keyname || strlen(keyname) == 0) {
        free(keyname);
        free(keytype);
        return sendError(sh, msg, "keyname is required");
    }

    if (hasBadChars(keyname, strlen(keyname))) {
        free(keyname);
        free(keytype);
        return sendError(sh, msg, "keyname contains invalid characters");
    }

    // Get owner from application ID
    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) {
        app_id = LSMessageGetSenderServiceName(msg);
    }
    if (!app_id) {
        app_id = "unknown";
    }

    // Determine algorithm from keytype
    ushort algo = CKeyManager::stringToAlgorithm(keytype ? keytype : "aes");
    ushort type = KEY_TYPE_SECRET;

    // Build flags
    ushort flags = 0;
    if (nohide) flags |= 1;
    if (backup) flags |= 4;

    CKey* key = self->key_manager->generateKey(app_id, keyname, keybits, algo, type);

    char response[256];
    if (key) {
        snprintf(response, sizeof(response), "{\"returnValue\":true}");
        delete key;
    } else {
        snprintf(response, sizeof(response),
                 "{\"returnValue\":false,\"errorText\":\"Failed to generate key\"}");
    }

    free(keyname);
    free(keytype);

    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Store key - from decompilation @ 0x000141bc
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbStore(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    if (self->rejectIfInBackup(sh, msg)) {
        return true;
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* keydata = getStringParam(payload, "keydata");
    char* keytype = getStringParam(payload, "keytype");

    if (!keyname || !keydata) {
        free(keyname);
        free(keydata);
        free(keytype);
        return sendError(sh, msg, "keyname and keydata are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    // Decode base64 key data
    uchar* decoded_data = NULL;
    int decoded_len = 0;
    base64dec(keydata, &decoded_data, &decoded_len);

    if (!decoded_data || decoded_len == 0) {
        free(keyname);
        free(keydata);
        free(keytype);
        return sendError(sh, msg, "Invalid keydata encoding");
    }

    ushort algo = CKeyManager::stringToAlgorithm(keytype ? keytype : "blob");
    ushort type = KEY_TYPE_SECRET;

    int key_id = self->key_manager->storeKey(app_id, keyname, decoded_data, decoded_len, algo, type);

    OPENSSL_cleanse(decoded_data, decoded_len);
    free(decoded_data);

    char response[256];
    if (key_id >= 0) {
        snprintf(response, sizeof(response), "{\"returnValue\":true}");
    } else {
        snprintf(response, sizeof(response),
                 "{\"returnValue\":false,\"errorText\":\"Failed to store key\"}");
    }

    free(keyname);
    free(keydata);
    free(keytype);

    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Fetch key - from decompilation @ 0x0001327c
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbFetch(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    if (!keyname) {
        return sendError(sh, msg, "keyname is required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    CKey* key = self->key_manager->fetchKey(app_id, keyname);

    if (!key) {
        free(keyname);
        return sendError(sh, msg, "Key not found");
    }

    // Encode key data as base64
    char* encoded = base64enc((uchar*)key->data(), key->dataLength());

    char* response = (char*)malloc(strlen(encoded) + 512);
    snprintf(response, strlen(encoded) + 512,
             "{\"returnValue\":true,\"keyname\":\"%s\",\"type\":\"%s\",\"keydata\":\"%s\"}",
             keyname,
             CKeyManager::typeToString(key->type),
             encoded ? encoded : "");

    free(encoded);
    delete key;
    free(keyname);

    bool result = sendSuccess(sh, msg, response);
    free(response);
    return result;
}

//-----------------------------------------------------------------------------
// Remove key - from decompilation @ 0x00013f44
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbRemove(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    if (self->rejectIfInBackup(sh, msg)) {
        return true;
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    if (!keyname) {
        return sendError(sh, msg, "keyname is required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int result = self->key_manager->removeKey(app_id, keyname);

    char response[256];
    snprintf(response, sizeof(response), "{\"returnValue\":%s}",
             result == 0 ? "true" : "false");

    free(keyname);
    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Crypt - from decompilation @ 0x000115ec
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbCrypt(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* data_str = getStringParam(payload, "data");
    char* mode_str = getStringParam(payload, "mode");
    char* iv_str = getStringParam(payload, "iv");
    bool decrypt = getBoolParam(payload, "decrypt", false);

    if (!keyname || !data_str) {
        free(keyname);
        free(data_str);
        free(mode_str);
        free(iv_str);
        return sendError(sh, msg, "keyname and data are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    // Get key ID
    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        free(data_str);
        free(mode_str);
        free(iv_str);
        return sendError(sh, msg, "Key not found");
    }

    // Decode input data
    uchar* in_data = NULL;
    int in_len = 0;
    base64dec(data_str, &in_data, &in_len);

    // Decode IV if provided
    uchar* iv = NULL;
    int iv_len = 0;
    if (iv_str) {
        base64dec(iv_str, &iv, &iv_len);
    }

    // Determine mode and padding
    ushort mode = CKeyManager::stringToMode(mode_str ? mode_str : "cbc");
    ushort pad = PAD_PKCS7;
    ushort op = decrypt ? CRYPT_DECRYPT : CRYPT_ENCRYPT;

    // Allocate output buffer (larger than input for padding)
    int blocksize = self->key_manager->blocksize(key_id);
    if (blocksize < 16) blocksize = 16;
    int out_size = in_len + blocksize;
    uchar* out_data = (uchar*)malloc(out_size);
    int out_len = 0;

    int result = self->key_manager->crypt(key_id, mode, pad, op,
                                          iv, iv_len, in_data, in_len,
                                          out_data, &out_len);

    char* response;
    if (result == 0) {
        char* encoded = base64enc(out_data, out_len);
        response = (char*)malloc(strlen(encoded) + 128);
        snprintf(response, strlen(encoded) + 128,
                 "{\"returnValue\":true,\"data\":\"%s\"}", encoded);
        free(encoded);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"Encryption failed\"}");
    }

    OPENSSL_cleanse(out_data, out_size);
    free(out_data);
    free(in_data);
    free(iv);
    free(keyname);
    free(data_str);
    free(mode_str);
    free(iv_str);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// File encrypt - from decompilation @ 0x00011310
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbFileEncrypt(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* srcpath = getStringParam(payload, "srcFilePath");
    char* dstpath = getStringParam(payload, "dstFilePath");

    if (!keyname || !srcpath || !dstpath) {
        free(keyname);
        free(srcpath);
        free(dstpath);
        return sendError(sh, msg, "keyname, srcFilePath, and dstFilePath are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        free(srcpath);
        free(dstpath);
        return sendError(sh, msg, "Key not found");
    }

    int result = self->key_manager->fileEncrypt(key_id, srcpath, dstpath);

    char response[256];
    snprintf(response, sizeof(response), "{\"returnValue\":%s}",
             result == 0 ? "true" : "false");

    free(keyname);
    free(srcpath);
    free(dstpath);

    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// File decrypt - from decompilation @ 0x000110a0
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbFileDecrypt(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* srcpath = getStringParam(payload, "srcFilePath");
    char* dstpath = getStringParam(payload, "dstFilePath");
    char* password = getStringParam(payload, "password");

    if (!srcpath || !dstpath) {
        free(srcpath);
        free(dstpath);
        free(password);
        return sendError(sh, msg, "srcFilePath and dstFilePath are required");
    }

    int result = self->key_manager->fileDecrypt(srcpath, dstpath, password);

    char response[256];
    snprintf(response, sizeof(response), "{\"returnValue\":%s}",
             result == 0 ? "true" : "false");

    if (password) {
        OPENSSL_cleanse(password, strlen(password));
    }
    free(srcpath);
    free(dstpath);
    free(password);

    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Export wrapped key - from decompilation @ 0x00011f80
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbExport(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* wrapkey = getStringParam(payload, "wrappingkeyname");

    if (!keyname || !wrapkey) {
        free(keyname);
        free(wrapkey);
        return sendError(sh, msg, "keyname and wrappingkeyname are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    int wrap_id = self->key_manager->fetchKeyId(app_id, wrapkey);

    if (key_id < 0 || wrap_id < 0) {
        free(keyname);
        free(wrapkey);
        return sendError(sh, msg, "Key not found");
    }

    char* wrapped = self->key_manager->exportWrappedKey(key_id, wrap_id);

    char* response;
    if (wrapped) {
        response = (char*)malloc(strlen(wrapped) + 128);
        snprintf(response, strlen(wrapped) + 128,
                 "{\"returnValue\":true,\"wrappedkey\":\"%s\"}", wrapped);
        free(wrapped);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"Export failed\"}");
    }

    free(keyname);
    free(wrapkey);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// Import wrapped key - from decompilation @ 0x00013c38
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbImport(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    if (self->rejectIfInBackup(sh, msg)) {
        return true;
    }

    const char* payload = LSMessageGetPayload(msg);

    char* wrapped = getStringParam(payload, "wrappedkey");
    if (!wrapped) {
        return sendError(sh, msg, "wrappedkey is required");
    }

    int key_id = self->key_manager->importWrappedKey(wrapped);

    char response[256];
    if (key_id > 0) {
        CKey* info = self->key_manager->keyInfo(key_id);
        if (info) {
            snprintf(response, sizeof(response),
                     "{\"returnValue\":true,\"keyname\":\"%s\"}", info->name);
            delete info;
        } else {
            snprintf(response, sizeof(response), "{\"returnValue\":true}");
        }
    } else {
        snprintf(response, sizeof(response),
                 "{\"returnValue\":false,\"errorText\":\"Import failed\"}");
    }

    free(wrapped);
    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Key info
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbKeyInfo(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    if (!keyname) {
        return sendError(sh, msg, "keyname is required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        return sendError(sh, msg, "Key not found");
    }

    CKey* info = self->key_manager->keyInfo(key_id);
    if (!info) {
        free(keyname);
        return sendError(sh, msg, "Failed to get key info");
    }

    char response[512];
    snprintf(response, sizeof(response),
             "{\"returnValue\":true,\"keyname\":\"%s\",\"algorithm\":\"%s\","
             "\"type\":\"%s\",\"size\":%d}",
             info->name,
             CKey::algorithmName(info->algorithm),
             CKeyManager::typeToString(info->type),
             info->key_size);

    delete info;
    free(keyname);

    return sendSuccess(sh, msg, response);
}

//-----------------------------------------------------------------------------
// Hash - from decompilation
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbHash(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* data_str = getStringParam(payload, "data");
    char* algo_str = getStringParam(payload, "algorithm");

    if (!data_str) {
        free(algo_str);
        return sendError(sh, msg, "data is required");
    }

    // Decode input
    uchar* in_data = NULL;
    int in_len = 0;
    base64dec(data_str, &in_data, &in_len);

    ushort algo = CKeyManager::stringToAlgorithm(algo_str ? algo_str : "sha1");

    uchar hash_out[64];
    int hash_len = sizeof(hash_out);

    int result = CKeyManager::hash(algo, in_data, in_len, hash_out, &hash_len);

    char* response;
    if (result == 0) {
        char* encoded = base64enc(hash_out, hash_len);
        response = (char*)malloc(strlen(encoded) + 128);
        snprintf(response, strlen(encoded) + 128,
                 "{\"returnValue\":true,\"hash\":\"%s\"}", encoded);
        free(encoded);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"Hash failed\"}");
    }

    free(in_data);
    free(data_str);
    free(algo_str);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// HMAC
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbHmac(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* data_str = getStringParam(payload, "data");

    if (!keyname || !data_str) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "keyname and data are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "Key not found");
    }

    uchar* in_data = NULL;
    int in_len = 0;
    base64dec(data_str, &in_data, &in_len);

    uchar hmac_out[64];
    int hmac_len = sizeof(hmac_out);

    int result = self->key_manager->hmac(key_id, in_data, in_len, hmac_out, &hmac_len);

    char* response;
    if (result == 0) {
        char* encoded = base64enc(hmac_out, hmac_len);
        response = (char*)malloc(strlen(encoded) + 128);
        snprintf(response, strlen(encoded) + 128,
                 "{\"returnValue\":true,\"hmac\":\"%s\"}", encoded);
        free(encoded);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"HMAC failed\"}");
    }

    free(in_data);
    free(keyname);
    free(data_str);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// RSA Encrypt
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbRsaEncrypt(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* data_str = getStringParam(payload, "data");

    if (!keyname || !data_str) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "keyname and data are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "Key not found");
    }

    uchar* in_data = NULL;
    int in_len = 0;
    base64dec(data_str, &in_data, &in_len);

    uchar out_data[512];
    int out_len = sizeof(out_data);

    int result = self->key_manager->rsaEncrypt(key_id, in_data, in_len, out_data, &out_len);

    char* response;
    if (result == 0) {
        char* encoded = base64enc(out_data, out_len);
        response = (char*)malloc(strlen(encoded) + 128);
        snprintf(response, strlen(encoded) + 128,
                 "{\"returnValue\":true,\"data\":\"%s\"}", encoded);
        free(encoded);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"RSA encrypt failed\"}");
    }

    free(in_data);
    free(keyname);
    free(data_str);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// RSA Decrypt
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbRsaDecrypt(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    const char* payload = LSMessageGetPayload(msg);

    char* keyname = getStringParam(payload, "keyname");
    char* data_str = getStringParam(payload, "data");

    if (!keyname || !data_str) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "keyname and data are required");
    }

    const char* app_id = LSMessageGetApplicationID(msg);
    if (!app_id) app_id = LSMessageGetSenderServiceName(msg);
    if (!app_id) app_id = "unknown";

    int key_id = self->key_manager->fetchKeyId(app_id, keyname);
    if (key_id < 0) {
        free(keyname);
        free(data_str);
        return sendError(sh, msg, "Key not found");
    }

    uchar* in_data = NULL;
    int in_len = 0;
    base64dec(data_str, &in_data, &in_len);

    uchar out_data[512];
    int out_len = sizeof(out_data);

    int result = self->key_manager->rsaDecrypt(key_id, in_data, in_len, out_data, &out_len);

    char* response;
    if (result == 0) {
        char* encoded = base64enc(out_data, out_len);
        response = (char*)malloc(strlen(encoded) + 128);
        snprintf(response, strlen(encoded) + 128,
                 "{\"returnValue\":true,\"data\":\"%s\"}", encoded);
        OPENSSL_cleanse(out_data, out_len);
        free(encoded);
    } else {
        response = strdup("{\"returnValue\":false,\"errorText\":\"RSA decrypt failed\"}");
    }

    free(in_data);
    free(keyname);
    free(data_str);

    bool success = sendSuccess(sh, msg, response);
    free(response);
    return success;
}

//-----------------------------------------------------------------------------
// Backup service callbacks - from decompilation @ 0x000109e4
//-----------------------------------------------------------------------------

bool KeyServiceHandler::cbPreBackup(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self) {
        return sendError(sh, msg, "Service not initialized");
    }

    self->in_backup = true;

    // Return backup file information
    return sendSuccess(sh, msg,
        "{\"returnValue\":true,"
        "\"description\":\"Key database\","
        "\"files\":[\"/var/palm/data/keys.db\"]}");
}

bool KeyServiceHandler::cbPostBackup(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self) {
        return sendError(sh, msg, "Service not initialized");
    }

    self->in_backup = false;

    return sendSuccess(sh, msg, "{\"returnValue\":true}");
}

bool KeyServiceHandler::cbPreRestore(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self) {
        return sendError(sh, msg, "Service not initialized");
    }

    self->in_restore = true;

    return sendSuccess(sh, msg, "{\"returnValue\":true}");
}

bool KeyServiceHandler::cbPostRestore(LSHandle* sh, LSMessage* msg, void* ctx)
{
    KeyServiceHandler* self = (KeyServiceHandler*)ctx;
    if (!self || !self->key_manager) {
        return sendError(sh, msg, "Service not initialized");
    }

    self->in_restore = false;

    // Re-initialize key manager after restore
    // The decompilation shows this reinitializes the database

    return sendSuccess(sh, msg, "{\"returnValue\":true}");
}

//-----------------------------------------------------------------------------
// KeyServiceApp Implementation - from decompilation @ 0x0000f0f8
//-----------------------------------------------------------------------------

KeyServiceApp::KeyServiceApp()
    : main_loop(NULL), service_handle(NULL), key_manager(NULL), handler(NULL)
{
}

KeyServiceApp::~KeyServiceApp()
{
    shutdown();
}

int KeyServiceApp::initKeyManager()
{
    // Try to initialize with PIN if available
    Passcode passcode;
    if (passcode.pin_set()) {
        char* pin = NULL;
        if (passcode.get_pin(&pin) == 0 && pin) {
            int result = key_manager->initialize(
                "/var/palm/data/keys.db",
                pin,
                "N11LunaKeyMgmt13CKeyExceptionE"
            );
            OPENSSL_cleanse(pin, strlen(pin));
            free(pin);
            if (result == 0) {
                return 0;
            }
        }
    }

    // Fall back to initialization without PIN
    return key_manager->initialize(
        "/var/palm/data/keys.db",
        NULL,
        "N11LunaKeyMgmt13CKeyExceptionE"
    );
}

int KeyServiceApp::init(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    LSError lserror;
    LSErrorInit(&lserror);

    // Create main loop
    main_loop = g_main_loop_new(NULL, FALSE);
    if (!main_loop) {
        fprintf(stderr, "Failed to create main loop\n");
        return -1;
    }

    // Register service
    if (!LSRegister("com.palm.keymanager", &service_handle, &lserror)) {
        fprintf(stderr, "Failed to register service: %s\n", lserror.message);
        LSErrorFree(&lserror);
        return -1;
    }

    // Attach to main loop
    if (!LSGmainAttach(service_handle, main_loop, &lserror)) {
        fprintf(stderr, "Failed to attach to main loop: %s\n", lserror.message);
        LSErrorFree(&lserror);
        return -1;
    }

    // Create key manager
    key_manager = new CKeyManager();

    // Initialize key manager
    if (initKeyManager() != 0) {
        fprintf(stderr, "Warning: Key manager initialization failed\n");
        // Continue anyway - some operations may still work
    }

    // Create and initialize handler
    handler = new KeyServiceHandler(service_handle, key_manager);
    if (handler->init() != 0) {
        fprintf(stderr, "Failed to initialize service handler\n");
        return -1;
    }

    return 0;
}

int KeyServiceApp::run()
{
    if (!main_loop) {
        return -1;
    }

    g_main_loop_run(main_loop);
    return 0;
}

void KeyServiceApp::shutdown()
{
    LSError lserror;
    LSErrorInit(&lserror);

    if (handler) {
        delete handler;
        handler = NULL;
    }

    if (key_manager) {
        key_manager->finish();
        delete key_manager;
        key_manager = NULL;
    }

    if (service_handle) {
        LSUnregister(service_handle, &lserror);
        service_handle = NULL;
    }

    if (main_loop) {
        g_main_loop_unref(main_loop);
        main_loop = NULL;
    }
}

//-----------------------------------------------------------------------------
// Main entry point
//-----------------------------------------------------------------------------

int main(int argc, char** argv)
{
    KeyServiceApp app;

    if (app.init(argc, argv) != 0) {
        fprintf(stderr, "Failed to initialize keymanager service\n");
        return 1;
    }

    return app.run();
}
