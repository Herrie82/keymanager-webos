/*
 * Test program for reconstructed keymanager KDF
 * Verifies the key derivation implementation
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <openssl/evp.h>
#include "keymanager_types.h"

// Helper to print hex
void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("Keymanager KDF Test\n");
    printf("===================\n\n");

    // Test password and salt
    const char* password = "testpassword";
    const char* salt = "testsalt";

    printf("Password: %s\n", password);
    printf("Salt: %s\n", salt);
    printf("\n");

    try {
        // Test 1: With device ID appended (default mode)
        printf("Test 1: genKeyAndIVFromPassword with append_device_id=true\n");
        {
            LunaKeyMgmt::CPassword pwd(password, salt, true);

            uchar* key = NULL;
            uchar* iv = NULL;
            int key_len = 0, iv_len = 0;

            pwd.getKeyAndIv(&key, &key_len, &iv, &iv_len);

            printf("  Key length: %d bytes\n", key_len);
            printf("  IV length: %d bytes\n", iv_len);
            print_hex("  Key", key, key_len);
            print_hex("  IV", iv, iv_len);
        }
        printf("\n");

        // Test 2: Without device ID
        printf("Test 2: genKeyAndIVFromPassword with append_device_id=false\n");
        {
            LunaKeyMgmt::CPassword pwd(password, salt, false);

            uchar* key = NULL;
            uchar* iv = NULL;
            int key_len = 0, iv_len = 0;

            pwd.getKeyAndIv(&key, &key_len, &iv, &iv_len);

            printf("  Key length: %d bytes\n", key_len);
            printf("  IV length: %d bytes\n", iv_len);
            print_hex("  Key", key, key_len);
            print_hex("  IV", iv, iv_len);
        }
        printf("\n");

        // Test 3: DeviceID generation
        printf("Test 3: DeviceID generation\n");
        {
            LunaKeyMgmt::DeviceID device_id;
            char* id = device_id.get();
            printf("  DeviceID: %s\n", id ? id : "(null)");
            printf("  Length: %zu chars\n", id ? strlen(id) : 0);
        }
        printf("\n");

        printf("All tests completed successfully!\n");

    } catch (std::exception& ex) {
        printf("Error: %s\n", ex.what());
        return 1;
    }

    return 0;
}
