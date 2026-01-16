/*
 * KeyManager Mojo Service Implementation
 * Full Mojo Framework Integration for webOS 3.0.5
 *
 * Uses MojLunaService + MojGmainReactor with SQLite key storage
 * API compatible with original webOS 3.0.5 keymanager
 */

#include "keyservice_mojo.h"
#include "keymanager_types.h"
#include "keymanager_constants.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// Service name
const MojChar* const KeyServiceMojoApp::ServiceName = _T("com.palm.keymanager");

/*
 * Base64 encode/decode helpers
 */
static MojErr base64Encode(const unsigned char* data, int len, MojString& out)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM* bufPtr;
    BIO_get_mem_ptr(b64, &bufPtr);

    MojErr err = out.assign(bufPtr->data, bufPtr->length);
    BIO_free_all(b64);

    return err;
}

static int base64Decode(const MojChar* input, unsigned char* output, int maxLen)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf((void*)input, -1);
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    int len = BIO_read(b64, output, maxLen);
    BIO_free_all(b64);

    return len;
}

//=============================================================================
// KeyServiceMojoHandler
//=============================================================================

KeyServiceMojoHandler::KeyServiceMojoHandler(LunaKeyMgmt::CKeyManager* keymanager)
    : m_keymanager(keymanager)
    , m_inBackup(false)
    , m_inRestore(false)
{
}

KeyServiceMojoHandler::~KeyServiceMojoHandler()
{
}

MojErr KeyServiceMojoHandler::init()
{
    MojErr err;

    // Register methods (schema=NULL, flags=0 for all)
    err = addMethod(_T("generate"), (Callback)&KeyServiceMojoHandler::handleGenerate);
    MojErrCheck(err);
    err = addMethod(_T("store"), (Callback)&KeyServiceMojoHandler::handleStore);
    MojErrCheck(err);
    err = addMethod(_T("fetch"), (Callback)&KeyServiceMojoHandler::handleFetch);
    MojErrCheck(err);
    err = addMethod(_T("remove"), (Callback)&KeyServiceMojoHandler::handleRemove);
    MojErrCheck(err);
    err = addMethod(_T("keyInfo"), (Callback)&KeyServiceMojoHandler::handleKeyInfo);
    MojErrCheck(err);
    err = addMethod(_T("crypt"), (Callback)&KeyServiceMojoHandler::handleCrypt);
    MojErrCheck(err);
    err = addMethod(_T("fileEncrypt"), (Callback)&KeyServiceMojoHandler::handleFileEncrypt);
    MojErrCheck(err);
    err = addMethod(_T("fileDecrypt"), (Callback)&KeyServiceMojoHandler::handleFileDecrypt);
    MojErrCheck(err);
    err = addMethod(_T("export"), (Callback)&KeyServiceMojoHandler::handleExport);
    MojErrCheck(err);
    err = addMethod(_T("import"), (Callback)&KeyServiceMojoHandler::handleImport);
    MojErrCheck(err);
    err = addMethod(_T("hash"), (Callback)&KeyServiceMojoHandler::handleHash);
    MojErrCheck(err);
    err = addMethod(_T("hmac"), (Callback)&KeyServiceMojoHandler::handleHmac);
    MojErrCheck(err);
    err = addMethod(_T("rsaEncrypt"), (Callback)&KeyServiceMojoHandler::handleRsaEncrypt);
    MojErrCheck(err);
    err = addMethod(_T("rsaDecrypt"), (Callback)&KeyServiceMojoHandler::handleRsaDecrypt);
    MojErrCheck(err);
    err = addMethod(_T("preBackup"), (Callback)&KeyServiceMojoHandler::handlePreBackup);
    MojErrCheck(err);
    err = addMethod(_T("postBackup"), (Callback)&KeyServiceMojoHandler::handlePostBackup);
    MojErrCheck(err);
    err = addMethod(_T("preRestore"), (Callback)&KeyServiceMojoHandler::handlePreRestore);
    MojErrCheck(err);
    err = addMethod(_T("postRestore"), (Callback)&KeyServiceMojoHandler::handlePostRestore);
    MojErrCheck(err);

    return MojErrNone;
}

bool KeyServiceMojoHandler::hasBadChars(const MojChar* str)
{
    if (!str) return true;

    while (*str) {
        char c = *str;
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return true;
        }
        str++;
    }
    return false;
}

MojErr KeyServiceMojoHandler::replyError(MojServiceMessage* msg, MojErr code, const MojChar* text)
{
    MojObject reply;
    reply.putBool(_T("returnValue"), false);
    reply.putInt(_T("errorCode"), (MojInt64)code);
    if (text) {
        reply.putString(_T("errorText"), text);
    }
    return msg->reply(reply);
}

MojErr KeyServiceMojoHandler::replySuccess(MojServiceMessage* msg)
{
    MojObject reply;
    reply.putBool(_T("returnValue"), true);
    return msg->reply(reply);
}

MojErr KeyServiceMojoHandler::replySuccess(MojServiceMessage* msg, MojObject& payload)
{
    payload.putBool(_T("returnValue"), true);
    return msg->reply(payload);
}

MojErr KeyServiceMojoHandler::rejectIfInBackup(MojServiceMessage* msg)
{
    if (m_inBackup || m_inRestore) {
        return replyError(msg, MojErrAccessDenied, _T("Operation not allowed during backup/restore"));
    }
    return MojErrNone;
}

//-----------------------------------------------------------------------------
// Key Management Methods
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleGenerate(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner, typeStr;
    bool found;

    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    if (hasBadChars(keyname.data()) || hasBadChars(owner.data())) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid characters in keyname or owner"));
    }

    err = payload.get(_T("type"), typeStr, found);
    MojErrCheck(err);

    // Get size - MojInt64 get returns bool directly
    MojInt64 size64 = 256;
    payload.get(_T("size"), size64);
    int size = (int)size64;

    // Determine algorithm and type
    ushort algo = LunaKeyMgmt::KEY_ALG_AES;
    ushort keyType = LunaKeyMgmt::KEY_TYPE_SECRET;

    if (found && typeStr.length() > 0) {
        if (typeStr == _T("RSA") || typeStr == _T("rsa")) {
            algo = LunaKeyMgmt::KEY_ALG_RSA;
            keyType = LunaKeyMgmt::KEY_TYPE_PRIVATE;
        }
    }

    // Generate key
    LunaKeyMgmt::CKey* key = m_keymanager->generateKey(
        owner.data(), keyname.data(), size, algo, keyType);

    if (!key) {
        return replyError(msg, MojErrInternal, _T("Key generation failed"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    delete key;
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleStore(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner, typeStr, dataStr;
    bool found;

    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    if (hasBadChars(keyname.data()) || hasBadChars(owner.data())) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid characters in keyname or owner"));
    }

    // Decode base64 data
    unsigned char keyData[4096];
    int keyLen = base64Decode(dataStr.data(), keyData, sizeof(keyData));
    if (keyLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Determine algorithm and type
    err = payload.get(_T("type"), typeStr, found);
    ushort algo = LunaKeyMgmt::KEY_ALG_AES;
    ushort keyType = LunaKeyMgmt::KEY_TYPE_SECRET;

    if (found && typeStr.length() > 0) {
        if (typeStr == _T("RSA") || typeStr == _T("rsa")) {
            algo = LunaKeyMgmt::KEY_ALG_RSA;
            keyType = LunaKeyMgmt::KEY_TYPE_PRIVATE;
        } else if (typeStr == _T("RSA_PUB") || typeStr == _T("rsa_pub")) {
            algo = LunaKeyMgmt::KEY_ALG_RSA;
            keyType = LunaKeyMgmt::KEY_TYPE_PUBLIC;
        }
    }

    // Store key
    int result = m_keymanager->storeKey(owner.data(), keyname.data(),
                                         keyData, keyLen, algo, keyType);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("Key storage failed"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleFetch(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    if (hasBadChars(keyname.data()) || hasBadChars(owner.data())) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid characters in keyname or owner"));
    }

    // Fetch key
    LunaKeyMgmt::CKey* key = m_keymanager->fetchKey(owner.data(), keyname.data());
    if (!key) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Encode key data as base64
    MojString dataStr;
    base64Encode((unsigned char*)key->key_data, key->data_length, dataStr);

    // Build reply
    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    reply.putString(_T("owner"), owner);
    reply.putString(_T("data"), dataStr);
    reply.putString(_T("type"), key->keyTypeName());
    reply.putInt(_T("size"), key->key_size);

    delete key;
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleRemove(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner;
    bool found;

    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    if (hasBadChars(keyname.data()) || hasBadChars(owner.data())) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid characters in keyname or owner"));
    }

    int result = m_keymanager->removeKey(owner.data(), keyname.data());
    if (result != 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handleKeyInfo(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    // Fetch key info
    LunaKeyMgmt::CKey* key = m_keymanager->keyInfo(owner.data(), keyname.data());
    if (!key) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    reply.putString(_T("owner"), owner);
    reply.putString(_T("type"), key->keyTypeName());
    reply.putString(_T("algorithm"), key->algorithmName());
    reply.putInt(_T("size"), key->key_size);

    delete key;
    return replySuccess(msg, reply);
}

//-----------------------------------------------------------------------------
// Encryption Methods
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleCrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, dataStr, modeStr, padStr;
    bool decrypt = false;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    payload.get(_T("decrypt"), decrypt);

    // Get mode and padding
    err = payload.get(_T("mode"), modeStr, found);
    ushort mode = LunaKeyMgmt::MODE_CBC;
    if (found && modeStr.length() > 0) {
        mode = LunaKeyMgmt::CKeyManager::stringToMode(modeStr.data());
    }

    err = payload.get(_T("padding"), padStr, found);
    ushort pad = LunaKeyMgmt::PAD_PKCS7;
    if (found && padStr.length() > 0) {
        pad = LunaKeyMgmt::CKeyManager::stringToPad(padStr.data());
    }

    // Get key ID
    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Decode input data
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Perform encryption/decryption
    unsigned char outData[65536 + 32];
    int outLen = sizeof(outData);

    ushort op = decrypt ? LunaKeyMgmt::CRYPT_DECRYPT : LunaKeyMgmt::CRYPT_ENCRYPT;
    int result = m_keymanager->crypt((ushort)keyId, mode, pad, op,
                                     NULL, 0, inData, inLen, outData, &outLen);

    if (result != 0) {
        return replyError(msg, MojErrInternal, decrypt ? _T("Decryption failed") : _T("Encryption failed"));
    }

    // Encode output
    MojString outStr;
    base64Encode(outData, outLen, outStr);

    MojObject reply;
    reply.putString(_T("data"), outStr);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleFileEncrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner, inPath, outPath;
    bool found;

    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("infile"), inPath, found);
    MojErrCheck(err);
    if (!found || inPath.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("infile required"));
    }

    err = payload.get(_T("outfile"), outPath, found);
    MojErrCheck(err);
    if (!found || outPath.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("outfile required"));
    }

    // Get key ID
    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    int result = m_keymanager->fileEncrypt((ushort)keyId, inPath.data(), outPath.data());
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("File encryption failed"));
    }

    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handleFileDecrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString inPath, outPath, password;
    bool found;

    err = payload.get(_T("infile"), inPath, found);
    MojErrCheck(err);
    if (!found || inPath.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("infile required"));
    }

    err = payload.get(_T("outfile"), outPath, found);
    MojErrCheck(err);
    if (!found || outPath.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("outfile required"));
    }

    err = payload.get(_T("password"), password, found);
    const char* pass = found ? password.data() : NULL;

    int result = m_keymanager->fileDecrypt(inPath.data(), outPath.data(), pass);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("File decryption failed"));
    }

    return replySuccess(msg);
}

//-----------------------------------------------------------------------------
// Key Export/Import
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleExport(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, wrapKeyname;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("wrapKey"), wrapKeyname, found);
    MojErrCheck(err);
    if (!found || wrapKeyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("wrapKey required"));
    }

    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    int wrapKeyId = m_keymanager->fetchKeyId(owner.data(), wrapKeyname.data());
    if (wrapKeyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Wrap key not found"));
    }

    char* wrapped = m_keymanager->exportWrappedKey((ushort)keyId, (ushort)wrapKeyId);
    if (!wrapped) {
        return replyError(msg, MojErrInternal, _T("Key export failed"));
    }

    MojObject reply;
    reply.putString(_T("data"), wrapped);
    free(wrapped);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleImport(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString dataStr;
    bool found;

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    int result = m_keymanager->importWrappedKey(dataStr.data());
    if (result < 0) {
        return replyError(msg, MojErrInternal, _T("Key import failed"));
    }

    MojObject reply;
    reply.putInt(_T("keyId"), result);
    return replySuccess(msg, reply);
}

//-----------------------------------------------------------------------------
// Hash Operations
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleHash(MojServiceMessage* msg, MojObject& payload)
{
    MojString algorithm, dataStr;
    bool found;

    MojErr err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    err = payload.get(_T("algorithm"), algorithm, found);
    ushort algo = LunaKeyMgmt::KEY_ALG_SHA1;
    if (found && algorithm.length() > 0) {
        algo = LunaKeyMgmt::CKeyManager::stringToAlgorithm(algorithm.data());
    }

    // Decode input
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Compute hash
    unsigned char hash[64];
    int hashLen = sizeof(hash);

    int result = LunaKeyMgmt::CKeyManager::hash(algo, inData, inLen, hash, &hashLen);
    if (result != 0) {
        return replyError(msg, MojErrInvalidArg, _T("Hash computation failed"));
    }

    MojString hashStr;
    base64Encode(hash, hashLen, hashStr);

    MojObject reply;
    reply.putString(_T("hash"), hashStr);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleHmac(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, dataStr;
    bool found;

    MojErr err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    // Get key ID
    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Decode input
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Compute HMAC
    unsigned char mac[64];
    int macLen = sizeof(mac);

    int result = m_keymanager->hmac((ushort)keyId, inData, inLen, mac, &macLen);
    if (result != 0) {
        return replyError(msg, MojErrInvalidArg, _T("HMAC computation failed"));
    }

    MojString macStr;
    base64Encode(mac, macLen, macStr);

    MojObject reply;
    reply.putString(_T("hmac"), macStr);
    return replySuccess(msg, reply);
}

//-----------------------------------------------------------------------------
// RSA Operations
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleRsaEncrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, dataStr;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    // Get key ID
    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Decode input
    unsigned char inData[512];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // RSA encrypt
    unsigned char outData[512];
    int outLen = sizeof(outData);

    int result = m_keymanager->rsaEncrypt((ushort)keyId, inData, inLen, outData, &outLen);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("RSA encryption failed"));
    }

    MojString outStr;
    base64Encode(outData, outLen, outStr);

    MojObject reply;
    reply.putString(_T("data"), outStr);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleRsaDecrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, dataStr;
    bool found;

    MojErr err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        owner.assign(msg->senderId());
    }

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    // Get key ID
    int keyId = m_keymanager->fetchKeyId(owner.data(), keyname.data());
    if (keyId < 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Decode input
    unsigned char inData[512];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // RSA decrypt
    unsigned char outData[512];
    int outLen = sizeof(outData);

    int result = m_keymanager->rsaDecrypt((ushort)keyId, inData, inLen, outData, &outLen);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("RSA decryption failed"));
    }

    MojString outStr;
    base64Encode(outData, outLen, outStr);

    MojObject reply;
    reply.putString(_T("data"), outStr);
    return replySuccess(msg, reply);
}

//-----------------------------------------------------------------------------
// Backup/Restore
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handlePreBackup(MojServiceMessage* msg, MojObject& payload)
{
    m_inBackup = true;

    MojString password, salt, path;
    bool found;

    MojErr err = payload.get(_T("password"), password, found);
    MojErrCheck(err);
    if (!found || password.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("password required"));
    }

    err = payload.get(_T("salt"), salt, found);
    const char* saltStr = found ? salt.data() : NULL;

    err = payload.get(_T("path"), path, found);
    const char* pathStr = found ? path.data() : "/tmp/keymanager-backup.db";

    int result = m_keymanager->backup(pathStr, password.data(), saltStr);
    if (result != 0) {
        m_inBackup = false;
        return replyError(msg, MojErrInternal, _T("Backup failed"));
    }

    MojObject reply;
    reply.putString(_T("backupFile"), pathStr);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handlePostBackup(MojServiceMessage* msg, MojObject& payload)
{
    m_inBackup = false;
    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handlePreRestore(MojServiceMessage* msg, MojObject& payload)
{
    m_inRestore = true;
    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handlePostRestore(MojServiceMessage* msg, MojObject& payload)
{
    MojString password, salt, path;
    bool found;

    MojErr err = payload.get(_T("password"), password, found);
    MojErrCheck(err);
    if (!found || password.empty()) {
        m_inRestore = false;
        return replyError(msg, MojErrInvalidArg, _T("password required"));
    }

    err = payload.get(_T("salt"), salt, found);
    const char* saltStr = found ? salt.data() : NULL;

    err = payload.get(_T("path"), path, found);
    const char* pathStr = found ? path.data() : "/tmp/keymanager-backup.db";

    int result = m_keymanager->restore(pathStr, password.data(), saltStr);
    m_inRestore = false;

    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("Restore failed"));
    }

    return replySuccess(msg);
}

//=============================================================================
// KeyServiceMojoApp
//=============================================================================

KeyServiceMojoApp::KeyServiceMojoApp()
    : m_keymanager(NULL)
    , m_initialized(false)
{
}

KeyServiceMojoApp::~KeyServiceMojoApp()
{
    shutdown();
}

MojErr KeyServiceMojoApp::init()
{
    MojErr err;

    // Initialize reactor
    err = m_reactor.init();
    MojErrCheck(err);

    // Initialize keymanager
    m_keymanager = new LunaKeyMgmt::CKeyManager();
    int result = m_keymanager->initialize(NULL, NULL, NULL);
    if (result != 0) {
        fprintf(stderr, "CKeyManager::initialize failed: %d\n", result);
        return MojErrInternal;
    }

    // Open Luna service
    err = m_service.open(ServiceName);
    MojErrCheck(err);

    // Attach to GLib main loop
    err = m_service.attach(m_reactor.impl());
    MojErrCheck(err);

    // Create and init handler
    m_handler.reset(new KeyServiceMojoHandler(m_keymanager));
    err = m_handler->init();
    MojErrCheck(err);

    // Register category
    err = m_service.addCategory(_T("/"), m_handler.get());
    MojErrCheck(err);

    m_initialized = true;
    fprintf(stderr, "KeyServiceMojoApp initialized successfully\n");

    return MojErrNone;
}

MojErr KeyServiceMojoApp::run()
{
    if (!m_initialized) {
        MojErr err = init();
        MojErrCheck(err);
    }

    fprintf(stderr, "KeyServiceMojoApp::run() - entering main loop\n");
    return m_reactor.run();
}

MojErr KeyServiceMojoApp::shutdown()
{
    fprintf(stderr, "KeyServiceMojoApp::shutdown()\n");

    m_reactor.stop();
    m_service.close();

    if (m_keymanager) {
        m_keymanager->finish();
        delete m_keymanager;
        m_keymanager = NULL;
    }

    m_initialized = false;
    return MojErrNone;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    KeyServiceMojoApp app;

    MojErr err = app.run();
    if (err != MojErrNone) {
        fprintf(stderr, "Application failed with error: %d\n", err);
        return 1;
    }

    return 0;
}
