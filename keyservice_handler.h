/*
 * KeyServiceHandler - Luna Service Method Handlers
 * Reconstructed from Ghidra decompilation @ 0x0000e7ec - 0x00014300
 * Handles keymanager service requests over Luna Service bus
 */

#ifndef KEYSERVICE_HANDLER_H
#define KEYSERVICE_HANDLER_H

#include "keymanager_types.h"
#include <lunaservice.h>
#include <glib.h>

/*
 * KeyServiceHandler - Handles Luna Service method calls for keymanager
 *
 * Service name: com.palm.keymanager
 * Categories:
 *   /  (root) - private methods
 *   /pub - public methods (limited set)
 *
 * Methods from decompilation:
 *   - generate: Generate new key (0x000138bc)
 *   - store: Store key data (0x000141bc)
 *   - fetch: Retrieve key (0x0001327c)
 *   - remove: Delete key (0x00013f44)
 *   - crypt: Encrypt/decrypt data (0x000115ec)
 *   - fileEncrypt: Encrypt file (0x00011310)
 *   - fileDecrypt: Decrypt file (0x000110a0)
 *   - export: Export wrapped key (0x00011f80)
 *   - import: Import wrapped key (0x00013c38)
 *   - preBackup: Backup preparation (0x000109e4)
 *   - postBackup: Backup completion (0x0001238c)
 *   - preRestore: Restore preparation (0x00012858)
 *   - postRestore: Restore completion (0x00010454)
 */
class KeyServiceHandler {
private:
    LSHandle* service_handle;
    LunaKeyMgmt::CKeyManager* key_manager;
    bool in_backup;
    bool in_restore;

    // Static method tables for Luna Service registration
    static LSMethod s_priv_methods[];
    static LSMethod s_pub_methods[];

    // Singleton instance for callback context
    static KeyServiceHandler* s_instance;

public:
    KeyServiceHandler(LSHandle* handle, LunaKeyMgmt::CKeyManager* km);
    ~KeyServiceHandler();

    // Initialize and register methods
    int init();

    // Helper to validate input strings
    static bool hasBadChars(const char* str, int len);

    // Check if backup is in progress
    bool isInBackup() const { return in_backup; }
    bool isInRestore() const { return in_restore; }

    // Get key manager
    LunaKeyMgmt::CKeyManager* getKeyManager() { return key_manager; }

    // Get singleton instance
    static KeyServiceHandler* instance() { return s_instance; }

private:
    // Service method implementations (static for Luna callbacks)

    // Key generation and storage
    static bool cbGenerate(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbStore(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbFetch(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbRemove(LSHandle* sh, LSMessage* msg, void* ctx);

    // Encryption operations
    static bool cbCrypt(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbFileEncrypt(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbFileDecrypt(LSHandle* sh, LSMessage* msg, void* ctx);

    // Key export/import
    static bool cbExport(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbImport(LSHandle* sh, LSMessage* msg, void* ctx);

    // Backup service integration
    static bool cbPreBackup(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbPostBackup(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbPreRestore(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbPostRestore(LSHandle* sh, LSMessage* msg, void* ctx);

    // Key info
    static bool cbKeyInfo(LSHandle* sh, LSMessage* msg, void* ctx);

    // Hash operations
    static bool cbHash(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbHmac(LSHandle* sh, LSMessage* msg, void* ctx);

    // RSA operations
    static bool cbRsaEncrypt(LSHandle* sh, LSMessage* msg, void* ctx);
    static bool cbRsaDecrypt(LSHandle* sh, LSMessage* msg, void* ctx);

    // Helper to send error response
    static bool sendError(LSHandle* sh, LSMessage* msg, const char* error_text);

    // Helper to send success response
    static bool sendSuccess(LSHandle* sh, LSMessage* msg, const char* payload);

    // Helper to check backup state and reject if in backup
    bool rejectIfInBackup(LSHandle* sh, LSMessage* msg);

    // Parse JSON from message
    static char* getStringParam(const char* payload, const char* key);
    static int getIntParam(const char* payload, const char* key, int default_val);
    static bool getBoolParam(const char* payload, const char* key, bool default_val);
};

/*
 * KeyServiceApp - Main application for keymanager service
 * From decompilation @ 0x0000f0f8 (Init)
 */
class KeyServiceApp {
private:
    GMainLoop* main_loop;
    LSHandle* service_handle;
    LunaKeyMgmt::CKeyManager* key_manager;
    KeyServiceHandler* handler;

public:
    KeyServiceApp();
    ~KeyServiceApp();

    // Initialize service
    int init(int argc, char** argv);

    // Run main loop
    int run();

    // Shutdown
    void shutdown();

private:
    // Initialize the key manager with PIN if available
    int initKeyManager();
};

#endif /* KEYSERVICE_HANDLER_H */
