/*
 * KeyManager Mojo Service Implementation
 * Full Mojo Framework Integration for webOS 3.0.5
 *
 * Uses MojLunaService + MojGmainReactor with SQLite key storage
 */

#include "keyservice_mojo.h"
#include "keymanager_types.h"
#include "ckeymanager.cpp"  // Include for CKeyManager

#include "core/MojLogDb8.h"

#include <cstring>
#include <cstdlib>

// Service name
const MojChar* const KeyServiceMojoApp::ServiceName = _T("com.palm.keymanager");

// Logging
static MojLogger s_log(_T("keymanager"));

/*
 * Base64 encode/decode helpers
 */
static MojErr base64Encode(const unsigned char* data, int len, MojString& out)
{
    // Use OpenSSL BIO for base64 encoding
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
    BIO* mem = BIO_new_mem_buf(input, -1);
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

    // Register private methods
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
    err = addMethod(_T("hash"), (Callback)&KeyServiceMojoHandler::handleHash, true);  // public
    MojErrCheck(err);
    err = addMethod(_T("hmac"), (Callback)&KeyServiceMojoHandler::handleHmac, true);  // public
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
        // Allow alphanumeric, dots, underscores, hyphens
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
    MojInt64 size = 256;

    bool found;
    err = payload.get(_T("keyname"), keyname, found);
    MojErrCheck(err);
    if (!found || keyname.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("keyname required"));
    }

    err = payload.get(_T("owner"), owner, found);
    MojErrCheck(err);
    if (!found || owner.empty()) {
        // Use sender as owner
        owner.assign(msg->senderId());
    }

    if (hasBadChars(keyname.data()) || hasBadChars(owner.data())) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid characters in keyname or owner"));
    }

    err = payload.get(_T("type"), typeStr, found);
    MojErrCheck(err);

    payload.get(_T("size"), size, found);

    // Determine key type
    LunaKeyMgmt::KeyType keyType = LunaKeyMgmt::KEY_AES;
    if (found && typeStr.length() > 0) {
        if (typeStr == _T("RSA") || typeStr == _T("rsa")) {
            keyType = LunaKeyMgmt::KEY_RSA_PAIR;
        }
    }

    // Generate key
    int result = m_keymanager->generateKey(keyname.data(), owner.data(), keyType, (int)size);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("Key generation failed"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleStore(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner, typeStr, dataStr;
    MojInt64 size = 256;
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

    // Determine key type
    err = payload.get(_T("type"), typeStr, found);
    LunaKeyMgmt::KeyType keyType = LunaKeyMgmt::KEY_AES;
    if (found && typeStr.length() > 0) {
        if (typeStr == _T("RSA") || typeStr == _T("rsa")) {
            keyType = LunaKeyMgmt::KEY_RSA_PAIR;
        }
    }

    payload.get(_T("size"), size, found);

    // Create and store key
    LunaKeyMgmt::CKey key;
    key.setKeyName(keyname.data());
    key.setOwner(owner.data());
    key.setType(keyType);
    key.setSize((int)size);
    key.setKeyData(keyData, keyLen);

    int result = m_keymanager->storeKey(&key);
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
    LunaKeyMgmt::CKey key;
    int result = m_keymanager->fetchKey(keyname.data(), owner.data(), &key);
    if (result != 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // Encode key data as base64
    MojString dataStr;
    base64Encode(key.getKeyData(), key.getKeyDataLen(), dataStr);

    // Build reply
    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    reply.putString(_T("owner"), owner);
    reply.putString(_T("data"), dataStr);

    const char* typeStr = "AES";
    switch (key.getType()) {
        case LunaKeyMgmt::KEY_RSA_PUB: typeStr = "RSA_PUB"; break;
        case LunaKeyMgmt::KEY_RSA_PRIV: typeStr = "RSA_PRIV"; break;
        case LunaKeyMgmt::KEY_RSA_PAIR: typeStr = "RSA_PAIR"; break;
        default: break;
    }
    reply.putString(_T("type"), typeStr);
    reply.putInt(_T("size"), key.getSize());

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

    int result = m_keymanager->removeKey(keyname.data(), owner.data());
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

    // Fetch key (without data)
    LunaKeyMgmt::CKey key;
    int result = m_keymanager->fetchKey(keyname.data(), owner.data(), &key);
    if (result != 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
    reply.putString(_T("owner"), owner);

    const char* typeStr = "AES";
    switch (key.getType()) {
        case LunaKeyMgmt::KEY_RSA_PUB: typeStr = "RSA_PUB"; break;
        case LunaKeyMgmt::KEY_RSA_PRIV: typeStr = "RSA_PRIV"; break;
        case LunaKeyMgmt::KEY_RSA_PAIR: typeStr = "RSA_PAIR"; break;
        default: break;
    }
    reply.putString(_T("type"), typeStr);
    reply.putInt(_T("size"), key.getSize());

    return replySuccess(msg, reply);
}

//-----------------------------------------------------------------------------
// Encryption Methods
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleCrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, dataStr;
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

    payload.get(_T("decrypt"), decrypt, found);

    // Decode input data
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Perform encryption/decryption
    unsigned char outData[65536 + 32];
    int outLen = sizeof(outData);

    int result;
    if (decrypt) {
        result = m_keymanager->decrypt(keyname.data(), owner.data(),
                                       inData, inLen, outData, &outLen);
    } else {
        result = m_keymanager->encrypt(keyname.data(), owner.data(),
                                       inData, inLen, outData, &outLen);
    }

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

    // TODO: Implement file encryption via CFileCrypt
    return replyError(msg, MojErrNotImplemented, _T("File encryption not implemented"));
}

MojErr KeyServiceMojoHandler::handleFileDecrypt(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString inPath, outPath;
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

    // TODO: Implement file decryption via CFileCrypt
    return replyError(msg, MojErrNotImplemented, _T("File decryption not implemented"));
}

//-----------------------------------------------------------------------------
// Key Export/Import
//-----------------------------------------------------------------------------

MojErr KeyServiceMojoHandler::handleExport(MojServiceMessage* msg, MojObject& payload)
{
    MojString keyname, owner, password;
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

    err = payload.get(_T("password"), password, found);
    MojErrCheck(err);
    if (!found || password.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("password required"));
    }

    unsigned char exportData[8192];
    int exportLen = sizeof(exportData);

    int result = m_keymanager->exportKey(keyname.data(), owner.data(),
                                         password.data(), exportData, &exportLen);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("Key export failed"));
    }

    MojString dataStr;
    base64Encode(exportData, exportLen, dataStr);

    MojObject reply;
    reply.putString(_T("data"), dataStr);
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handleImport(MojServiceMessage* msg, MojObject& payload)
{
    MojErr err = rejectIfInBackup(msg);
    MojErrCheck(err);

    MojString keyname, owner, password, dataStr;
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

    err = payload.get(_T("password"), password, found);
    MojErrCheck(err);
    if (!found || password.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("password required"));
    }

    err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    unsigned char importData[8192];
    int importLen = base64Decode(dataStr.data(), importData, sizeof(importData));
    if (importLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    int result = m_keymanager->importKey(keyname.data(), owner.data(),
                                         password.data(), importData, importLen);
    if (result != 0) {
        return replyError(msg, MojErrInternal, _T("Key import failed"));
    }

    MojObject reply;
    reply.putString(_T("keyname"), keyname);
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
    if (!found || algorithm.empty()) {
        algorithm.assign(_T("sha256"));
    }

    // Decode input
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Compute hash
    LunaKeyMgmt::CCrypto crypto;
    unsigned char hash[64];
    int hashLen = sizeof(hash);

    int result = crypto.hash(algorithm.data(), inData, inLen, hash, &hashLen);
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
    MojString algorithm, keyStr, dataStr;
    bool found;

    MojErr err = payload.get(_T("data"), dataStr, found);
    MojErrCheck(err);
    if (!found || dataStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("data required"));
    }

    err = payload.get(_T("key"), keyStr, found);
    MojErrCheck(err);
    if (!found || keyStr.empty()) {
        return replyError(msg, MojErrInvalidArg, _T("key required"));
    }

    err = payload.get(_T("algorithm"), algorithm, found);
    if (!found || algorithm.empty()) {
        algorithm.assign(_T("sha256"));
    }

    // Decode inputs
    unsigned char inData[65536];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    unsigned char keyData[256];
    int keyLen = base64Decode(keyStr.data(), keyData, sizeof(keyData));
    if (keyLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 key"));
    }

    // Compute HMAC
    LunaKeyMgmt::CCrypto crypto;
    unsigned char mac[64];
    int macLen = sizeof(mac);

    int result = crypto.hmac(algorithm.data(), keyData, keyLen, inData, inLen, mac, &macLen);
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

    // Decode input
    unsigned char inData[512];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Get key
    LunaKeyMgmt::CKey key;
    int result = m_keymanager->fetchKey(keyname.data(), owner.data(), &key);
    if (result != 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // RSA encrypt
    LunaKeyMgmt::CCrypto crypto;
    unsigned char outData[512];
    int outLen = sizeof(outData);

    result = crypto.rsaPublicEncrypt(key.getKeyData(), key.getKeyDataLen(),
                                     inData, inLen, outData, &outLen);
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

    // Decode input
    unsigned char inData[512];
    int inLen = base64Decode(dataStr.data(), inData, sizeof(inData));
    if (inLen <= 0) {
        return replyError(msg, MojErrInvalidArg, _T("Invalid base64 data"));
    }

    // Get key
    LunaKeyMgmt::CKey key;
    int result = m_keymanager->fetchKey(keyname.data(), owner.data(), &key);
    if (result != 0) {
        return replyError(msg, MojErrNotFound, _T("Key not found"));
    }

    // RSA decrypt
    LunaKeyMgmt::CCrypto crypto;
    unsigned char outData[512];
    int outLen = sizeof(outData);

    result = crypto.rsaPrivateDecrypt(key.getKeyData(), key.getKeyDataLen(),
                                      inData, inLen, outData, &outLen);
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

    // TODO: Export keys to backup file
    MojObject reply;
    reply.putString(_T("tempDir"), _T("/tmp/keymanager-backup"));
    return replySuccess(msg, reply);
}

MojErr KeyServiceMojoHandler::handlePostBackup(MojServiceMessage* msg, MojObject& payload)
{
    m_inBackup = false;

    // TODO: Cleanup backup temp files
    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handlePreRestore(MojServiceMessage* msg, MojObject& payload)
{
    m_inRestore = true;
    return replySuccess(msg);
}

MojErr KeyServiceMojoHandler::handlePostRestore(MojServiceMessage* msg, MojObject& payload)
{
    m_inRestore = false;

    // TODO: Import keys from backup
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

    MojLogInfo(s_log, _T("KeyServiceMojoApp::init()"));

    // Initialize reactor
    err = m_reactor.init();
    MojErrCheck(err);

    // Initialize keymanager
    m_keymanager = new LunaKeyMgmt::CKeyManager();
    int result = m_keymanager->init(NULL, NULL);  // Use default db path
    if (result != 0) {
        MojLogError(s_log, _T("CKeyManager::init failed: %d"), result);
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
    MojLogInfo(s_log, _T("KeyServiceMojoApp initialized successfully"));

    return MojErrNone;
}

MojErr KeyServiceMojoApp::run()
{
    if (!m_initialized) {
        MojErr err = init();
        MojErrCheck(err);
    }

    MojLogInfo(s_log, _T("KeyServiceMojoApp::run() - entering main loop"));
    return m_reactor.run();
}

MojErr KeyServiceMojoApp::shutdown()
{
    MojLogInfo(s_log, _T("KeyServiceMojoApp::shutdown()"));

    m_reactor.stop();
    m_service.close();

    if (m_keymanager) {
        m_keymanager->shutdown();
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
    KeyServiceMojoApp app;

    MojErr err = app.run();
    if (err != MojErrNone) {
        MojLogError(s_log, _T("Application failed with error: %d"), err);
        return 1;
    }

    return 0;
}
