/*
 * KeyManager Mojo Service - Full Mojo Framework Integration
 * Reconstructed from Ghidra decompilation of webOS 3.0.5 keymanager
 *
 * Uses MojLunaService for Luna bus integration with MojObject for JSON
 * Key storage remains in SQLite via CKeyStore (original architecture)
 */

#ifndef KEYSERVICE_MOJO_H_
#define KEYSERVICE_MOJO_H_

#include "core/MojCoreDefs.h"
#include "core/MojService.h"
#include "core/MojServiceMessage.h"
#include "core/MojObject.h"
#include "core/MojString.h"
#include "core/MojGmainReactor.h"
#include "luna/MojLunaService.h"

#include "keymanager_types.h"

// Forward declarations
namespace LunaKeyMgmt {
    class CKey;
    class CCrypto;
    class CPassword;
    class CKeyManager;
    class CFileCrypt;
}

/*
 * KeyServiceMojoHandler - Mojo CategoryHandler for keymanager methods
 * Handles all Luna service method calls using Mojo framework
 */
class KeyServiceMojoHandler : public MojService::CategoryHandler
{
public:
    KeyServiceMojoHandler(LunaKeyMgmt::CKeyManager* keymanager);
    virtual ~KeyServiceMojoHandler();

    // Initialize and register methods
    MojErr init();

protected:
    // Key management methods
    MojErr handleGenerate(MojServiceMessage* msg, MojObject& payload);
    MojErr handleStore(MojServiceMessage* msg, MojObject& payload);
    MojErr handleFetch(MojServiceMessage* msg, MojObject& payload);
    MojErr handleRemove(MojServiceMessage* msg, MojObject& payload);
    MojErr handleKeyInfo(MojServiceMessage* msg, MojObject& payload);

    // Encryption methods
    MojErr handleCrypt(MojServiceMessage* msg, MojObject& payload);
    MojErr handleFileEncrypt(MojServiceMessage* msg, MojObject& payload);
    MojErr handleFileDecrypt(MojServiceMessage* msg, MojObject& payload);

    // Key export/import
    MojErr handleExport(MojServiceMessage* msg, MojObject& payload);
    MojErr handleImport(MojServiceMessage* msg, MojObject& payload);

    // Hash operations
    MojErr handleHash(MojServiceMessage* msg, MojObject& payload);
    MojErr handleHmac(MojServiceMessage* msg, MojObject& payload);

    // RSA operations
    MojErr handleRsaEncrypt(MojServiceMessage* msg, MojObject& payload);
    MojErr handleRsaDecrypt(MojServiceMessage* msg, MojObject& payload);

    // Backup/restore
    MojErr handlePreBackup(MojServiceMessage* msg, MojObject& payload);
    MojErr handlePostBackup(MojServiceMessage* msg, MojObject& payload);
    MojErr handlePreRestore(MojServiceMessage* msg, MojObject& payload);
    MojErr handlePostRestore(MojServiceMessage* msg, MojObject& payload);

private:
    // Helper methods
    MojErr replyError(MojServiceMessage* msg, MojErr code, const MojChar* text);
    MojErr replySuccess(MojServiceMessage* msg);
    MojErr replySuccess(MojServiceMessage* msg, MojObject& payload);

    // Validate input strings for bad characters
    static bool hasBadChars(const MojChar* str);

    // Check backup state
    bool isInBackup() const { return m_inBackup; }
    bool isInRestore() const { return m_inRestore; }

    // Reject operations during backup
    MojErr rejectIfInBackup(MojServiceMessage* msg);

    LunaKeyMgmt::CKeyManager* m_keymanager;
    bool m_inBackup;
    bool m_inRestore;
};

/*
 * KeyServiceMojoApp - Main application using MojGmainReactor
 * Initializes Luna service and runs GLib main loop
 */
class KeyServiceMojoApp : public MojSignalHandler
{
public:
    static const MojChar* const ServiceName;

    KeyServiceMojoApp();
    virtual ~KeyServiceMojoApp();

    // Initialize service
    MojErr init();

    // Run main loop
    MojErr run();

    // Shutdown
    MojErr shutdown();

private:
    MojGmainReactor m_reactor;
    MojLunaService m_service;
    LunaKeyMgmt::CKeyManager* m_keymanager;
    MojRefCountedPtr<KeyServiceMojoHandler> m_handler;
    bool m_initialized;
};

// Main entry point
int main(int argc, char** argv);

#endif /* KEYSERVICE_MOJO_H_ */
