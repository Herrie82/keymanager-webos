/*
 * CKeyStore Implementation
 * Reconstructed from Ghidra decompilation @ 0x00019ba0 - 0x0001dc48
 */

#include "keymanager_types.h"
#include <sqlite3.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <stdexcept>

namespace LunaKeyMgmt {

// SQL statements for key database
static const char* SQL_CREATE_TABLE =
    "CREATE TABLE IF NOT EXISTS keys ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  owner TEXT NOT NULL,"
    "  name TEXT NOT NULL,"
    "  algorithm INTEGER NOT NULL,"
    "  type INTEGER NOT NULL,"
    "  key_size INTEGER NOT NULL,"
    "  data BLOB,"
    "  data_length INTEGER,"
    "  encrypted INTEGER DEFAULT 0,"
    "  hash BLOB,"
    "  hash_length INTEGER DEFAULT 0,"
    "  UNIQUE(owner, name)"
    ");";

static const char* SQL_INSERT_KEY =
    "INSERT INTO keys (owner, name, algorithm, type, key_size, data, data_length, encrypted, hash, hash_length) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

static const char* SQL_SELECT_KEY =
    "SELECT id, owner, name, algorithm, type, key_size, data, data_length, encrypted, hash, hash_length "
    "FROM keys WHERE id = ?;";

static const char* SQL_SELECT_KEY_BY_NAME =
    "SELECT id, owner, name, algorithm, type, key_size, data, data_length, encrypted, hash, hash_length "
    "FROM keys WHERE owner = ? AND name = ?;";

static const char* SQL_DELETE_KEY =
    "DELETE FROM keys WHERE id = ?;";

static const char* SQL_LIST_KEYS =
    "SELECT id, owner, name, algorithm, type, key_size FROM keys WHERE owner = ?;";

//-----------------------------------------------------------------------------
// CKeyStore Implementation
//-----------------------------------------------------------------------------

CKeyStore::CKeyStore() {
    db = NULL;
    master_key = NULL;
    master_key_length = 0;
    master_iv = NULL;
    master_iv_length = 0;
    is_unlocked = false;
    cache = new CKeyCache();
    stored_password = NULL;
    acct_token = NULL;
    db_path = DEFAULT_DB_PATH;
}

CKeyStore::~CKeyStore() {
    close();

    if (master_key) {
        OPENSSL_cleanse(master_key, master_key_length);
        PinnedMemory::Instance()->free(master_key);
        master_key = NULL;
    }
    if (master_iv) {
        OPENSSL_cleanse(master_iv, master_iv_length);
        free(master_iv);
        master_iv = NULL;
    }
    if (stored_password) {
        size_t len = strlen(stored_password);
        OPENSSL_cleanse(stored_password, len);
        free(stored_password);
        stored_password = NULL;
    }
    if (cache) {
        delete cache;
        cache = NULL;
    }
    if (acct_token) {
        delete acct_token;
        acct_token = NULL;
    }
}

int CKeyStore::connect() {
    if (db) {
        return 0;  // Already connected
    }

    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        const char* err = sqlite3_errmsg(db);
        sqlite3_close(db);
        db = NULL;
        throw std::runtime_error(std::string("Failed to open database: ") + err);
    }

    return 0;
}

void CKeyStore::close() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
    is_unlocked = false;
}

int CKeyStore::prep() {
    if (!db) {
        connect();
    }

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, SQL_CREATE_TABLE, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg;
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to create table: " + err);
    }

    return 0;
}

int CKeyStore::checkTable() {
    // Verify table exists and has correct schema
    const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='keys';";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_ROW) ? 0 : -1;
}

int CKeyStore::create(const char* password, const char* salt, bool use_device_id) {
    db_path = DEFAULT_DB_PATH;
    connect();
    prep();
    createAndStoreMasterKey(password, salt, use_device_id);
    return 0;
}

int CKeyStore::open(const char* dbpath, const char* password) {
    return open(dbpath, password, "", false, true);
}

int CKeyStore::open(const char* dbpath, const char* password, const char* salt) {
    return open(dbpath, password, salt, false, true);
}

int CKeyStore::open(const char* dbpath, const char* password, const char* salt, bool create_if_missing) {
    return open(dbpath, password, salt, create_if_missing, true);
}

int CKeyStore::open(const char* dbpath, const char* password, const char* salt, bool create_if_missing, bool use_device_id) {
    db_path = dbpath;

    int rc = sqlite3_open_v2(dbpath, &db,
                             create_if_missing ? (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
                                               : SQLITE_OPEN_READWRITE,
                             NULL);

    if (rc != SQLITE_OK) {
        const char* err = sqlite3_errmsg(db);
        sqlite3_close(db);
        db = NULL;
        throw std::runtime_error(std::string("Failed to open database: ") + err);
    }

    if (create_if_missing) {
        prep();
    }

    // Try to unlock
    if (masterKeyPresent()) {
        unlock(password, salt, use_device_id);
    } else if (create_if_missing) {
        createAndStoreMasterKey(password, salt, use_device_id);
    }

    return 0;
}

void CKeyStore::destroy() {
    close();
    if (!db_path.empty()) {
        remove(db_path.c_str());
    }
}

// From decompilation @ 0x0001a618
void CKeyStore::storeMasterKey(const char* password, const char* salt, bool create_new, bool use_device_id) {
    CPassword pwd(password, salt, use_device_id);

    uchar* new_key = NULL;
    uchar* new_iv = NULL;
    int key_len = 0, iv_len = 0;

    pwd.getKeyAndIv(&new_key, &key_len, &new_iv, &iv_len);

    // Free old keys
    if (master_key) {
        OPENSSL_cleanse(master_key, master_key_length);
        PinnedMemory::Instance()->free(master_key);
    }
    if (master_iv) {
        OPENSSL_cleanse(master_iv, master_iv_length);
        free(master_iv);
    }

    // Store new keys (copy from CPassword's memory)
    master_key_length = key_len;
    master_key = (uchar*)PinnedMemory::Instance()->malloc(key_len);
    memcpy(master_key, new_key, key_len);

    master_iv_length = iv_len;
    master_iv = (uchar*)malloc(iv_len);
    memcpy(master_iv, new_iv, iv_len);

    is_unlocked = true;

    // Store password for cloud key operations
    if (stored_password) {
        OPENSSL_cleanse(stored_password, strlen(stored_password));
        free(stored_password);
    }
    stored_password = strdup(password);
}

// From decompilation @ 0x0001b844
void CKeyStore::createAndStoreMasterKey(const char* password, const char* salt, bool use_device_id) {
    storeMasterKey(password, salt, false, use_device_id);
}

bool CKeyStore::masterKeyPresent() {
    return (master_key != NULL && master_key_length > 0);
}

int CKeyStore::unlock(const char* password, const char* salt, bool use_device_id) {
    storeMasterKey(password, salt, false, use_device_id);
    return 0;
}

void CKeyStore::lock() {
    if (master_key) {
        OPENSSL_cleanse(master_key, master_key_length);
        PinnedMemory::Instance()->free(master_key);
        master_key = NULL;
        master_key_length = 0;
    }
    if (master_iv) {
        OPENSSL_cleanse(master_iv, master_iv_length);
        free(master_iv);
        master_iv = NULL;
        master_iv_length = 0;
    }
    is_unlocked = false;

    // Clear cache
    if (cache) {
        cache->clean();
    }
}

bool CKeyStore::unlocked() {
    return is_unlocked;
}

// From decompilation @ 0x0001c6bc
int CKeyStore::insertKey(CKey* key) {
    if (!db) {
        throw std::runtime_error("Database not open");
    }

    // Encrypt key before storing
    encryptKey(key);

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, SQL_INSERT_KEY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert statement");
    }

    sqlite3_bind_text(stmt, 1, key->owner, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, key->algorithm);
    sqlite3_bind_int(stmt, 4, key->type);
    sqlite3_bind_int(stmt, 5, key->key_size);
    sqlite3_bind_blob(stmt, 6, key->key_data, key->data_length, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, key->data_length);
    sqlite3_bind_int(stmt, 8, key->encrypted ? 1 : 0);
    sqlite3_bind_blob(stmt, 9, key->hash_data, key->hash_length, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 10, key->hash_length);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert key");
    }

    key->key_id = (ushort)sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);

    // Add to cache
    addToCache(key);

    return 0;
}

int CKeyStore::deleteKey(ushort key_id) {
    if (!db) {
        throw std::runtime_error("Database not open");
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, SQL_DELETE_KEY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare delete statement");
    }

    sqlite3_bind_int(stmt, 1, key_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Remove from cache
    removeFromCache(key_id);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

CKey* CKeyStore::fetchEncryptedKey(ushort key_id) {
    if (!db) {
        throw std::runtime_error("Database not open");
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, SQL_SELECT_KEY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare select statement");
    }

    sqlite3_bind_int(stmt, 1, key_id);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    CKey* key = new CKey();
    key->key_id = sqlite3_column_int(stmt, 0);
    key->owner = strdup((const char*)sqlite3_column_text(stmt, 1));
    key->name = strdup((const char*)sqlite3_column_text(stmt, 2));
    key->algorithm = sqlite3_column_int(stmt, 3);
    key->type = sqlite3_column_int(stmt, 4);
    key->key_size = sqlite3_column_int(stmt, 5);

    int blob_size = sqlite3_column_bytes(stmt, 6);
    if (blob_size > 0) {
        key->key_data = malloc(blob_size);
        memcpy(key->key_data, sqlite3_column_blob(stmt, 6), blob_size);
    }
    key->data_length = sqlite3_column_int(stmt, 7);
    key->encrypted = (sqlite3_column_int(stmt, 8) != 0);

    int hash_size = sqlite3_column_bytes(stmt, 9);
    if (hash_size > 0) {
        key->hash_data = malloc(hash_size);
        memcpy(key->hash_data, sqlite3_column_blob(stmt, 9), hash_size);
    }
    key->hash_length = sqlite3_column_int(stmt, 10);

    sqlite3_finalize(stmt);
    return key;
}

CKey* CKeyStore::fetchAndDecryptKey(ushort key_id) {
    // Check cache first
    CKey* cached = getFromCache(key_id);
    if (cached) {
        return new CKey(cached);
    }

    CKey* key = fetchEncryptedKey(key_id);
    if (key && key->encrypted) {
        decryptKey(key);
        addToCache(key);
    }
    return key;
}

CKey* CKeyStore::fetchKeyInfo(ushort key_id) {
    CKey* key = fetchEncryptedKey(key_id);
    if (key) {
        // Clear data for info-only return
        if (key->key_data) {
            OPENSSL_cleanse(key->key_data, key->data_length);
            free(key->key_data);
            key->key_data = NULL;
        }
    }
    return key;
}

int CKeyStore::searchKey(const char* owner, const char* name) {
    if (!db) {
        throw std::runtime_error("Database not open");
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, SQL_SELECT_KEY_BY_NAME, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int key_id = -1;
    if (rc == SQLITE_ROW) {
        key_id = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return key_id;
}

// From decompilation @ 0x0001c274
void CKeyStore::encryptKey(CKey* key, uchar* wrap_key, int wrap_key_len, uchar* iv, int iv_len) {
    if (!wrap_key || !iv || wrap_key_len == 0 || iv_len == 0) {
        throw std::runtime_error("wrapping key not complete");
    }

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);

    if (block_size != wrap_key_len) {
        throw std::runtime_error("wrapping key size mismatch");
    }

    if (!key->encrypted) {
        int data_len = key->data_length;
        size_t out_size = block_size + data_len;
        uchar* out = (uchar*)malloc(out_size);
        memset(out, 0, out_size);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, cipher, NULL, wrap_key, iv);

        int out_len = out_size;
        EVP_EncryptUpdate(ctx, out, &out_len, (uchar*)key->key_data, data_len);

        int final_len = out_size - out_len;
        EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);

        EVP_CIPHER_CTX_free(ctx);

        // Securely clear original data
        OPENSSL_cleanse(key->key_data, key->data_length);
        free(key->key_data);

        key->key_data = out;
        key->data_length = out_len + final_len;
        key->encrypted = true;
    }
}

void CKeyStore::encryptKey(CKey* key) {
    if (!master_key || !master_iv) {
        throw std::runtime_error("master key not unlocked");
    }
    encryptKey(key, master_key, master_key_length, master_iv, master_iv_length);
}

void CKeyStore::decryptKey(CKey* key, uchar* wrap_key, int wrap_key_len, uchar* iv, int iv_len) {
    if (!wrap_key || !iv || wrap_key_len == 0 || iv_len == 0) {
        throw std::runtime_error("wrapping key not complete");
    }

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();

    if (key->encrypted) {
        int data_len = key->data_length;
        uchar* out = (uchar*)malloc(data_len);
        memset(out, 0, data_len);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, cipher, NULL, wrap_key, iv);

        int out_len = data_len;
        EVP_DecryptUpdate(ctx, out, &out_len, (uchar*)key->key_data, data_len);

        int final_len = data_len - out_len;
        EVP_DecryptFinal_ex(ctx, out + out_len, &final_len);

        EVP_CIPHER_CTX_free(ctx);

        // Replace encrypted data with decrypted
        OPENSSL_cleanse(key->key_data, key->data_length);
        free(key->key_data);

        key->key_data = out;
        key->data_length = out_len + final_len;
        key->encrypted = false;
    }
}

void CKeyStore::decryptKey(CKey* key) {
    if (!master_key || !master_iv) {
        throw std::runtime_error("master key not unlocked");
    }
    decryptKey(key, master_key, master_key_length, master_iv, master_iv_length);
}

void CKeyStore::hashKey(CKey* key, uchar** out_hash, int* out_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, key->key_data, key->data_length);

    *out_hash = (uchar*)malloc(EVP_MAX_MD_SIZE);
    uint len;
    EVP_DigestFinal(ctx, *out_hash, &len);
    *out_len = len;

    EVP_MD_CTX_free(ctx);
}

// Cache operations
void CKeyStore::addToCache(CKey* key) {
    if (cache) {
        cache->add(key);
    }
}

CKey* CKeyStore::getFromCache(ushort key_id) {
    if (cache) {
        return cache->get(key_id);
    }
    return NULL;
}

CKey* CKeyStore::getFromCache(const char* owner, const char* name) {
    if (cache) {
        return cache->get(owner, name);
    }
    return NULL;
}

void CKeyStore::removeFromCache(ushort key_id) {
    if (cache) {
        cache->remove(key_id);
    }
}

AcctToken* CKeyStore::getAcctToken() {
    return acct_token;
}

void CKeyStore::setAcctToken(AcctToken* token) {
    if (acct_token) {
        delete acct_token;
    }
    acct_token = token;
}

// Backup: Copy database and re-encrypt with new password
int CKeyStore::backup(const char* path, const char* password, const char* salt) {
    if (!db || !is_unlocked) {
        return -1;
    }

    // Open backup database
    sqlite3* backup_db;
    int rc = sqlite3_open(path, &backup_db);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Create table in backup
    char* err_msg = NULL;
    rc = sqlite3_exec(backup_db, SQL_CREATE_TABLE, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(backup_db);
        return -1;
    }

    // Derive backup encryption key
    CPassword pwd(password, salt, false);
    uchar* backup_key = NULL;
    uchar* backup_iv = NULL;
    int key_len = 0, iv_len = 0;
    pwd.getKeyAndIv(&backup_key, &key_len, &backup_iv, &iv_len);

    // Copy all keys - fetch, decrypt with current key, re-encrypt with backup key
    const char* sql = "SELECT id FROM keys;";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ushort key_id = sqlite3_column_int(stmt, 0);
            CKey* key = fetchAndDecryptKey(key_id);
            if (key) {
                // Re-encrypt with backup password
                encryptKey(key, backup_key, key_len, backup_iv, iv_len);

                // Insert into backup database
                sqlite3_stmt* ins_stmt;
                sqlite3_prepare_v2(backup_db, SQL_INSERT_KEY, -1, &ins_stmt, NULL);
                sqlite3_bind_text(ins_stmt, 1, key->owner, -1, SQLITE_STATIC);
                sqlite3_bind_text(ins_stmt, 2, key->name, -1, SQLITE_STATIC);
                sqlite3_bind_int(ins_stmt, 3, key->algorithm);
                sqlite3_bind_int(ins_stmt, 4, key->type);
                sqlite3_bind_int(ins_stmt, 5, key->key_size);
                sqlite3_bind_blob(ins_stmt, 6, key->key_data, key->data_length, SQLITE_STATIC);
                sqlite3_bind_int(ins_stmt, 7, key->data_length);
                sqlite3_bind_int(ins_stmt, 8, 1);  // encrypted
                sqlite3_step(ins_stmt);
                sqlite3_finalize(ins_stmt);

                delete key;
            }
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(backup_db);
    return 0;
}

int CKeyStore::restore(const char* path, const char* password, const char* salt) {
    return restore(path, password, salt, false);
}

int CKeyStore::restore(const char* path, const char* password, const char* salt, bool overwrite) {
    if (!db || !is_unlocked) {
        return -1;
    }

    // Open backup database
    sqlite3* backup_db;
    int rc = sqlite3_open_v2(path, &backup_db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Derive backup encryption key
    CPassword pwd(password, salt, false);
    uchar* backup_key = NULL;
    uchar* backup_iv = NULL;
    int key_len = 0, iv_len = 0;
    pwd.getKeyAndIv(&backup_key, &key_len, &backup_iv, &iv_len);

    // Read all keys from backup
    const char* sql = "SELECT id, owner, name, algorithm, type, key_size, data, data_length FROM keys;";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(backup_db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* owner = (const char*)sqlite3_column_text(stmt, 1);
            const char* name = (const char*)sqlite3_column_text(stmt, 2);

            // Check if key already exists
            int existing = searchKey(owner, name);
            if (existing >= 0 && !overwrite) {
                continue;  // Skip existing keys if not overwriting
            }

            // Create key from backup data
            CKey* key = new CKey();
            key->owner = strdup(owner);
            key->name = strdup(name);
            key->algorithm = sqlite3_column_int(stmt, 3);
            key->type = sqlite3_column_int(stmt, 4);
            key->key_size = sqlite3_column_int(stmt, 5);
            key->data_length = sqlite3_column_int(stmt, 7);
            key->key_data = malloc(key->data_length);
            memcpy(key->key_data, sqlite3_column_blob(stmt, 6), key->data_length);
            key->encrypted = true;

            // Decrypt with backup key
            decryptKey(key, backup_key, key_len, backup_iv, iv_len);

            // Re-encrypt with current master key and insert
            if (existing >= 0) {
                deleteKey(existing);
            }
            insertKey(key);
            delete key;
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(backup_db);
    return 0;
}

char* CKeyStore::exportWrappedKey(ushort key_id, ushort wrap_key_id) {
    CKey* key = fetchAndDecryptKey(key_id);
    if (!key) return NULL;

    CKey* wrap_key = fetchAndDecryptKey(wrap_key_id);
    if (!wrap_key) {
        delete key;
        return NULL;
    }

    CWrappedKey wrapped(key);
    wrapped.wrap(wrap_key);

    std::string encoded = wrapped.encode();
    char* result = strdup(encoded.c_str());

    delete key;
    delete wrap_key;
    return result;
}

int CKeyStore::importWrappedKey(const char* wrapped) {
    // Decode wrapped key
    CWrappedKey wk(wrapped);

    // TODO: Need wrapping key to unwrap
    // For now, return error - caller needs to provide wrapping key
    return -1;
}

// From decompilation @ 0x0001b7e4
int CKeyStore::changePassword(const char* old_pass, const char* new_pass, const char* salt, const char* new_salt) {
    if (!db) {
        return -1;
    }

    // Verify old password by trying to derive key
    CPassword old_pwd(old_pass, salt, true);
    uchar* old_key = NULL;
    uchar* old_iv = NULL;
    int old_key_len = 0, old_iv_len = 0;
    old_pwd.getKeyAndIv(&old_key, &old_key_len, &old_iv, &old_iv_len);

    // Check if it matches current master key
    if (memcmp(old_key, master_key, master_key_length) != 0) {
        return -1;  // Wrong password
    }

    // Derive new master key
    CPassword new_pwd(new_pass, new_salt, true);
    uchar* new_key = NULL;
    uchar* new_iv = NULL;
    int new_key_len = 0, new_iv_len = 0;
    new_pwd.getKeyAndIv(&new_key, &new_key_len, &new_iv, &new_iv_len);

    // Re-encrypt all keys with new master key
    const char* sql = "SELECT id FROM keys;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ushort key_id = sqlite3_column_int(stmt, 0);

            // Fetch and decrypt with old key
            CKey* key = fetchEncryptedKey(key_id);
            if (key) {
                decryptKey(key, old_key, old_key_len, old_iv, old_iv_len);

                // Re-encrypt with new key
                encryptKey(key, new_key, new_key_len, new_iv, new_iv_len);

                // Update in database
                const char* update_sql = "UPDATE keys SET data = ?, data_length = ? WHERE id = ?;";
                sqlite3_stmt* upd_stmt;
                sqlite3_prepare_v2(db, update_sql, -1, &upd_stmt, NULL);
                sqlite3_bind_blob(upd_stmt, 1, key->key_data, key->data_length, SQLITE_STATIC);
                sqlite3_bind_int(upd_stmt, 2, key->data_length);
                sqlite3_bind_int(upd_stmt, 3, key_id);
                sqlite3_step(upd_stmt);
                sqlite3_finalize(upd_stmt);

                delete key;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Update master key
    if (master_key) {
        OPENSSL_cleanse(master_key, master_key_length);
        PinnedMemory::Instance()->free(master_key);
    }
    if (master_iv) {
        OPENSSL_cleanse(master_iv, master_iv_length);
        free(master_iv);
    }

    master_key = (uchar*)PinnedMemory::Instance()->malloc(new_key_len);
    memcpy(master_key, new_key, new_key_len);
    master_key_length = new_key_len;

    master_iv = (uchar*)malloc(new_iv_len);
    memcpy(master_iv, new_iv, new_iv_len);
    master_iv_length = new_iv_len;

    // Clear cache
    if (cache) {
        cache->clean();
    }

    return 0;
}

int CKeyStore::cloudGetKeyBytes(CKey* key) {
    // Palm's cloud service is defunct
    CCloudKey cloud;
    return cloud.getKeyBytes(key, acct_token);
}

int CKeyStore::listKeys(const char* owner) {
    // TODO: Implement key listing
    (void)owner;
    return -1;
}

} // namespace LunaKeyMgmt
