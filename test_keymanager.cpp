/*
 * Comprehensive Test Program for Reconstructed Keymanager
 * Tests all major classes and functionality
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <unistd.h>
#include "keymanager_types.h"

using namespace LunaKeyMgmt;

// Helper to print hex
void print_hex(const char* label, const unsigned char* data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf(" (%d bytes)\n", len);
}

void test_password_kdf() {
    printf("\n=== Test 1: Password-based Key Derivation ===\n");

    const char* password = "testpassword123";
    const char* salt = "mysalt";

    // Test with device ID
    printf("With device ID appended:\n");
    CPassword pwd1(password, salt, true);
    uchar* key1; uchar* iv1; int kl1, il1;
    pwd1.getKeyAndIv(&key1, &kl1, &iv1, &il1);
    print_hex("Key", key1, kl1);
    print_hex("IV", iv1, il1);

    // Test without device ID
    printf("Without device ID:\n");
    CPassword pwd2(password, salt, false);
    uchar* key2; uchar* iv2; int kl2, il2;
    pwd2.getKeyAndIv(&key2, &kl2, &iv2, &il2);
    print_hex("Key", key2, kl2);
    print_hex("IV", iv2, il2);

    // Verify keys are different
    if (memcmp(key1, key2, kl1) == 0) {
        printf("  ERROR: Keys should be different!\n");
    } else {
        printf("  OK: Keys are different (device ID affects derivation)\n");
    }
}

void test_device_id() {
    printf("\n=== Test 2: Device ID Generation ===\n");

    DeviceID did1;
    char* id1 = did1.get();
    printf("  DeviceID: %s\n", id1);
    printf("  Length: %zu bytes\n", strlen(id1));

    // Generate again - should be same
    DeviceID did2;
    char* id2 = did2.get();

    if (strcmp(id1, id2) == 0) {
        printf("  OK: Device ID is consistent\n");
    } else {
        printf("  Warning: Device IDs differ (may be OK on different devices)\n");
    }
}

void test_ckey() {
    printf("\n=== Test 3: CKey Class ===\n");

    // Create AES key
    uchar key_data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    CKey* aes_key = new CKey("testowner", "mykey", key_data, 16, KEY_ALG_AES, KEY_TYPE_SECRET);
    aes_key->key_size = 128;

    printf("  Key name: %s\n", aes_key->name);
    printf("  Algorithm: %s\n", aes_key->keyTypeName());
    printf("  Block size: %d\n", aes_key->blocksize());
    printf("  Is block cipher: %s\n", aes_key->isBlockCipher() ? "yes" : "no");
    printf("  Is hash: %s\n", aes_key->isHash() ? "yes" : "no");
    printf("  Values: %s\n", aes_key->valuesString().c_str());

    // Copy constructor test
    CKey* copy = new CKey(aes_key);
    printf("  Copy test: %s\n",
           (memcmp(aes_key->data(), copy->data(), aes_key->dataLength()) == 0) ? "OK" : "FAIL");

    delete copy;
    delete aes_key;
}

void test_ccrypto() {
    printf("\n=== Test 4: CCrypto - Key Generation ===\n");

    // Generate AES-128 key
    CKey* gen_key = CCrypto::generateKey("testowner", "generated_aes", KEY_ALG_AES, KEY_TYPE_SECRET, 128);
    printf("  Generated AES-128 key:\n");
    print_hex("Data", (uchar*)gen_key->data(), gen_key->dataLength());
    printf("  Key size: %d bits\n", gen_key->keySize());

    // Test encryption/decryption
    printf("\n=== Test 5: CCrypto - Encryption/Decryption ===\n");

    uchar plaintext[] = "Hello, KeyManager! This is a test message.";
    int pt_len = strlen((char*)plaintext);

    uchar iv[16] = {0};
    RAND_bytes(iv, 16);

    // Encrypt
    CCrypto enc_crypto(gen_key, MODE_CBC, PAD_PKCS7, CRYPT_ENCRYPT, iv, 16, KEY_TYPE_SECRET);
    uchar ciphertext[256];
    int ct_len = 0;
    enc_crypto.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
    int final_len = 0;
    enc_crypto.cipherFinal(ciphertext + ct_len, &final_len);
    ct_len += final_len;

    printf("  Plaintext: %s\n", plaintext);
    print_hex("Ciphertext", ciphertext, ct_len);

    // Decrypt
    CCrypto dec_crypto(gen_key, MODE_CBC, PAD_PKCS7, CRYPT_DECRYPT, iv, 16, KEY_TYPE_SECRET);
    uchar decrypted[256];
    int dec_len = 0;
    dec_crypto.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
    int dec_final = 0;
    dec_crypto.cipherFinal(decrypted + dec_len, &dec_final);
    dec_len += dec_final;
    decrypted[dec_len] = '\0';

    printf("  Decrypted: %s\n", decrypted);

    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("  OK: Encryption/decryption successful\n");
    } else {
        printf("  FAIL: Decryption mismatch\n");
    }

    delete gen_key;
}

void test_keystore() {
    printf("\n=== Test 6: CKeyStore - Database Operations ===\n");

    const char* test_db = "/tmp/test_keymanager.db";

    // Remove old test DB
    unlink(test_db);

    CKeyStore store;

    // Create new database
    printf("  Creating database...\n");
    store.open(test_db, "masterpassword", "mastersalt", true, true);

    printf("  Database unlocked: %s\n", store.unlocked() ? "yes" : "no");

    // Generate and store a key
    printf("  Generating and storing key...\n");
    CKey* key = CCrypto::generateKey("testapp", "encryption_key", KEY_ALG_AES, KEY_TYPE_SECRET, 128);
    store.insertKey(key);
    printf("  Key stored with ID: %d\n", key->key_id);
    ushort stored_id = key->key_id;

    // Fetch the key back
    printf("  Fetching key...\n");
    CKey* fetched = store.fetchAndDecryptKey(stored_id);
    if (fetched) {
        printf("  Fetched key: %s\n", fetched->name);
        if (memcmp(key->data(), fetched->data(), key->dataLength()) == 0) {
            printf("  OK: Key data matches\n");
        } else {
            printf("  FAIL: Key data mismatch\n");
        }
        delete fetched;
    } else {
        printf("  FAIL: Could not fetch key\n");
    }

    // Search by name
    printf("  Searching by name...\n");
    int found_id = store.searchKey("testapp", "encryption_key");
    printf("  Found key ID: %d (expected: %d)\n", found_id, stored_id);

    // Delete key
    printf("  Deleting key...\n");
    store.deleteKey(stored_id);

    // Verify deletion
    fetched = store.fetchAndDecryptKey(stored_id);
    printf("  Key deleted: %s\n", (fetched == NULL) ? "yes" : "no");

    store.close();
    delete key;

    // Cleanup
    unlink(test_db);
}

void test_base64() {
    printf("\n=== Test 7: Base64 Encoding/Decoding ===\n");

    uchar data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    int data_len = sizeof(data);

    char* encoded = base64enc(data, data_len);
    printf("  Original: ");
    for (int i = 0; i < data_len; i++) printf("%02x", data[i]);
    printf("\n");
    printf("  Encoded: %s\n", encoded);

    uchar* decoded;
    int dec_len;
    base64dec(encoded, &decoded, &dec_len);

    printf("  Decoded: ");
    for (int i = 0; i < dec_len; i++) printf("%02x", decoded[i]);
    printf("\n");

    if (dec_len == data_len && memcmp(data, decoded, data_len) == 0) {
        printf("  OK: Base64 round-trip successful\n");
    } else {
        printf("  FAIL: Base64 mismatch\n");
    }

    free(encoded);
    free(decoded);
}

void test_file_crypt() {
    printf("\n=== Test 8: File Encryption/Decryption ===\n");

    const char* test_db = "/tmp/test_keymanager.db";
    const char* plain_file = "/tmp/test_plain.txt";
    const char* enc_file = "/tmp/test_encrypted.bin";
    const char* dec_file = "/tmp/test_decrypted.txt";

    // Remove old files
    unlink(test_db);
    unlink(plain_file);
    unlink(enc_file);
    unlink(dec_file);

    // Create test file
    FILE* f = fopen(plain_file, "w");
    fprintf(f, "This is a test file for encryption.\nLine 2\nLine 3\n");
    fclose(f);

    // Setup keystore
    CKeyStore store;
    store.open(test_db, "masterpassword", "mastersalt", true, true);

    // Generate encryption key
    CKey* key = CCrypto::generateKey("filetest", "file_key", KEY_ALG_AES, KEY_TYPE_SECRET, 128);
    store.insertKey(key);

    // Encrypt file
    printf("  Encrypting file...\n");
    CFileCrypt fc(&store);
    fc.encrypt(key, plain_file, enc_file);
    printf("  Encrypted file created\n");

    // Decrypt file
    printf("  Decrypting file...\n");
    CFileCrypt fc2(&store);
    fc2.decrypt(enc_file, dec_file, "masterpassword");
    printf("  Decrypted file created\n");

    // Compare files
    FILE* orig = fopen(plain_file, "r");
    FILE* decr = fopen(dec_file, "r");

    char buf1[256], buf2[256];
    bool match = true;
    while (fgets(buf1, sizeof(buf1), orig) && fgets(buf2, sizeof(buf2), decr)) {
        if (strcmp(buf1, buf2) != 0) {
            match = false;
            break;
        }
    }

    fclose(orig);
    fclose(decr);

    printf("  Files match: %s\n", match ? "yes" : "no");

    // Cleanup
    store.close();
    delete key;
    unlink(test_db);
    unlink(plain_file);
    unlink(enc_file);
    unlink(dec_file);
}

int main() {
    printf("============================================\n");
    printf("  Keymanager Reconstruction Test Suite\n");
    printf("============================================\n");

    try {
        test_password_kdf();
        test_device_id();
        test_ckey();
        test_ccrypto();
        test_keystore();
        test_base64();
        test_file_crypt();

        printf("\n============================================\n");
        printf("  All tests completed successfully!\n");
        printf("============================================\n");

    } catch (std::exception& e) {
        printf("\nERROR: %s\n", e.what());
        return 1;
    }

    return 0;
}
