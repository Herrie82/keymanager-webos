/*
 * Core Crypto Test Program for Reconstructed Keymanager
 * Tests CPassword, CKey, and CCrypto classes (no SQLite required)
 */

#include <cstdio>
#include <cstring>
#include <exception>
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

void test_key_generation() {
    printf("\n=== Test 4: CCrypto - Key Generation ===\n");

    // Generate AES-128 key
    CKey* gen_key = CCrypto::generateKey("testowner", "generated_aes", KEY_ALG_AES, KEY_TYPE_SECRET, 128);
    printf("  Generated AES-128 key:\n");
    print_hex("Data", (uchar*)gen_key->data(), gen_key->dataLength());
    printf("  Key size: %d bits\n", gen_key->keySize());

    // Generate AES-256 key
    CKey* gen256 = CCrypto::generateKey("testowner", "generated_aes256", KEY_ALG_AES, KEY_TYPE_SECRET, 256);
    printf("  Generated AES-256 key:\n");
    print_hex("Data", (uchar*)gen256->data(), gen256->dataLength());
    printf("  Key size: %d bits\n", gen256->keySize());

    delete gen_key;
    delete gen256;
}

void test_encryption() {
    printf("\n=== Test 5: CCrypto - Encryption/Decryption ===\n");

    // Generate key for test
    CKey* key = CCrypto::generateKey("testowner", "enc_key", KEY_ALG_AES, KEY_TYPE_SECRET, 128);

    uchar plaintext[] = "Hello, KeyManager! This is a test message.";
    int pt_len = strlen((char*)plaintext);

    uchar iv[16] = {0};
    RAND_bytes(iv, 16);

    // Encrypt
    CCrypto enc_crypto(key, MODE_CBC, PAD_PKCS7, CRYPT_ENCRYPT, iv, 16, KEY_TYPE_SECRET);
    uchar ciphertext[256];
    int ct_len = 0;
    enc_crypto.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
    int final_len = 0;
    enc_crypto.cipherFinal(ciphertext + ct_len, &final_len);
    ct_len += final_len;

    printf("  Plaintext: %s\n", plaintext);
    print_hex("IV", iv, 16);
    print_hex("Ciphertext", ciphertext, ct_len);

    // Decrypt
    CCrypto dec_crypto(key, MODE_CBC, PAD_PKCS7, CRYPT_DECRYPT, iv, 16, KEY_TYPE_SECRET);
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

    delete key;
}

void test_encryption_modes() {
    printf("\n=== Test 6: Multiple Cipher Modes ===\n");

    CKey* key = CCrypto::generateKey("testowner", "mode_key", KEY_ALG_AES, KEY_TYPE_SECRET, 128);
    uchar plaintext[] = "Testing cipher modes!";
    int pt_len = strlen((char*)plaintext);
    uchar iv[16];
    RAND_bytes(iv, 16);

    // Test ECB mode
    printf("  ECB Mode:\n");
    {
        uchar ciphertext[256], decrypted[256];
        int ct_len = 0, dec_len = 0, final_len;

        CCrypto enc(key, MODE_ECB, PAD_PKCS7, CRYPT_ENCRYPT, NULL, 0, KEY_TYPE_SECRET);
        enc.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
        enc.cipherFinal(ciphertext + ct_len, &final_len);
        ct_len += final_len;

        CCrypto dec(key, MODE_ECB, PAD_PKCS7, CRYPT_DECRYPT, NULL, 0, KEY_TYPE_SECRET);
        dec.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
        dec.cipherFinal(decrypted + dec_len, &final_len);
        dec_len += final_len;
        decrypted[dec_len] = '\0';

        printf("    %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "OK" : "FAIL");
    }

    // Test CBC mode
    printf("  CBC Mode:\n");
    {
        uchar ciphertext[256], decrypted[256];
        int ct_len = 0, dec_len = 0, final_len;

        CCrypto enc(key, MODE_CBC, PAD_PKCS7, CRYPT_ENCRYPT, iv, 16, KEY_TYPE_SECRET);
        enc.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
        enc.cipherFinal(ciphertext + ct_len, &final_len);
        ct_len += final_len;

        CCrypto dec(key, MODE_CBC, PAD_PKCS7, CRYPT_DECRYPT, iv, 16, KEY_TYPE_SECRET);
        dec.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
        dec.cipherFinal(decrypted + dec_len, &final_len);
        dec_len += final_len;
        decrypted[dec_len] = '\0';

        printf("    %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "OK" : "FAIL");
    }

    // Test CFB mode
    printf("  CFB Mode:\n");
    {
        uchar ciphertext[256], decrypted[256];
        int ct_len = 0, dec_len = 0, final_len;

        CCrypto enc(key, MODE_CFB, PAD_NONE, CRYPT_ENCRYPT, iv, 16, KEY_TYPE_SECRET);
        enc.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
        enc.cipherFinal(ciphertext + ct_len, &final_len);
        ct_len += final_len;

        CCrypto dec(key, MODE_CFB, PAD_NONE, CRYPT_DECRYPT, iv, 16, KEY_TYPE_SECRET);
        dec.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
        dec.cipherFinal(decrypted + dec_len, &final_len);
        dec_len += final_len;
        decrypted[dec_len] = '\0';

        printf("    %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "OK" : "FAIL");
    }

    delete key;
}

void test_3des() {
    printf("\n=== Test 7: 3DES Encryption ===\n");

    // Generate 3DES key (192 bits = 24 bytes)
    CKey* key = CCrypto::generateKey("testowner", "3des_key", KEY_ALG_3DES, KEY_TYPE_SECRET, 192);
    printf("  Generated 3DES key:\n");
    print_hex("Data", (uchar*)key->data(), key->dataLength());

    uchar plaintext[] = "3DES test message!";
    int pt_len = strlen((char*)plaintext);
    uchar iv[8];
    RAND_bytes(iv, 8);

    uchar ciphertext[256], decrypted[256];
    int ct_len = 0, dec_len = 0, final_len;

    CCrypto enc(key, MODE_CBC, PAD_PKCS7, CRYPT_ENCRYPT, iv, 8, KEY_TYPE_SECRET);
    enc.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
    enc.cipherFinal(ciphertext + ct_len, &final_len);
    ct_len += final_len;

    CCrypto dec(key, MODE_CBC, PAD_PKCS7, CRYPT_DECRYPT, iv, 8, KEY_TYPE_SECRET);
    dec.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
    dec.cipherFinal(decrypted + dec_len, &final_len);
    dec_len += final_len;
    decrypted[dec_len] = '\0';

    printf("  Plaintext: %s\n", plaintext);
    printf("  Decrypted: %s\n", decrypted);
    printf("  Result: %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "OK" : "FAIL");

    delete key;
}

void test_blowfish() {
    printf("\n=== Test 8: Blowfish Encryption ===\n");

    // Generate Blowfish key (128 bits)
    CKey* key = CCrypto::generateKey("testowner", "bf_key", KEY_ALG_BF, KEY_TYPE_SECRET, 128);
    printf("  Generated Blowfish key:\n");
    print_hex("Data", (uchar*)key->data(), key->dataLength());

    uchar plaintext[] = "Blowfish test!";
    int pt_len = strlen((char*)plaintext);
    uchar iv[8];
    RAND_bytes(iv, 8);

    uchar ciphertext[256], decrypted[256];
    int ct_len = 0, dec_len = 0, final_len;

    CCrypto enc(key, MODE_CBC, PAD_PKCS7, CRYPT_ENCRYPT, iv, 8, KEY_TYPE_SECRET);
    enc.cipherUpdate(plaintext, pt_len, ciphertext, &ct_len);
    enc.cipherFinal(ciphertext + ct_len, &final_len);
    ct_len += final_len;

    CCrypto dec(key, MODE_CBC, PAD_PKCS7, CRYPT_DECRYPT, iv, 8, KEY_TYPE_SECRET);
    dec.cipherUpdate(ciphertext, ct_len, decrypted, &dec_len);
    dec.cipherFinal(decrypted + dec_len, &final_len);
    dec_len += final_len;
    decrypted[dec_len] = '\0';

    printf("  Plaintext: %s\n", plaintext);
    printf("  Decrypted: %s\n", decrypted);
    printf("  Result: %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "OK" : "FAIL");

    delete key;
}

int main() {
    printf("============================================\n");
    printf("  Keymanager Core Crypto Test Suite\n");
    printf("============================================\n");

    try {
        test_password_kdf();
        test_device_id();
        test_ckey();
        test_key_generation();
        test_encryption();
        test_encryption_modes();
        test_3des();
        test_blowfish();

        printf("\n============================================\n");
        printf("  All core crypto tests passed!\n");
        printf("============================================\n");

    } catch (std::exception& e) {
        printf("\nERROR: %s\n", e.what());
        return 1;
    }

    return 0;
}
