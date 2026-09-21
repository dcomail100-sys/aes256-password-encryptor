#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char choice;
    char password[128];
    char text[512];
    unsigned char salt[16];
    unsigned char iv[16];
    unsigned char key[32];
    int salt_len = 16;
    int iv_len = 16;
    int key_len = 32;
    int iterations = 11000;

    printf("A = Encrypt\n");
    printf("B = Decrypt\n");
    printf("Enter choice (A/B): ");
    if (scanf(" %c", &choice) != 1) {
        printf("Invalid choice\n");
        return 1;
    }
    getchar();

    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Failed to read password\n");
        return 1;
    }
    password[strcspn(password, "\n")] = 0;

    if (choice == 'A' || choice == 'a') {
        printf("Enter text to encrypt: ");
        if (fgets(text, sizeof(text), stdin) == NULL) {
            printf("Failed to read text\n");
            return 1;
        }
        text[strcspn(text, "\n")] = 0;
        int plain_len = (int)strlen(text);

        if (RAND_bytes(salt, salt_len) != 1 || RAND_bytes(iv, iv_len) != 1) {
            printf("RAND_bytes failed\n");
            return 1;
        }

        if (PKCS5_PBKDF2_HMAC(password, -1, salt, salt_len, iterations,
                              EVP_sha256(), key_len, key) != 1) {
            printf("Key derivation failed\n");
            return 1;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            printf("Context failed\n");
            return 1;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            printf("EncryptInit failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        unsigned char ciphertext[512];
        int out1 = 0, out2 = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext, &out1,
                              (unsigned char *)text, plain_len) != 1) {
            printf("EncryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        if (EVP_EncryptFinal_ex(ctx, ciphertext + out1, &out2) != 1) {
            printf("EncryptFinal failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        int cipher_len = out1 + out2;
        printf("Encryption OK\n");
        printf("Cipher length: %d\n", cipher_len);

        printf("Salt: ");
        for (int i = 0; i < salt_len; i++) printf("%02x", salt[i]);
        printf("\n");

        printf("IV: ");
        for (int i = 0; i < iv_len; i++) printf("%02x", iv[i]);
        printf("\n");

        printf("Ciphertext: ");
        for (int i = 0; i < cipher_len; i++) printf("%02x", ciphertext[i]);
        printf("\n");

        EVP_CIPHER_CTX_free(ctx);
    }
    else if (choice == 'B' || choice == 'b') {
        char salt_hex[64];
        char iv_hex[64];
        char cipher_hex[1024];

        printf("Enter Salt (hex from A): ");
        if (fgets(salt_hex, sizeof(salt_hex), stdin) == NULL) return 1;
        salt_hex[strcspn(salt_hex, "\n")] = 0;

        printf("Enter IV (hex from A): ");
        if (fgets(iv_hex, sizeof(iv_hex), stdin) == NULL) return 1;
        iv_hex[strcspn(iv_hex, "\n")] = 0;

        printf("Enter Ciphertext (hex from A): ");
        if (fgets(cipher_hex, sizeof(cipher_hex), stdin) == NULL) return 1;
        cipher_hex[strcspn(cipher_hex, "\n")] = 0;

        /* convert hex to bytes */
        int i, j;
        for (i = 0, j = 0; salt_hex[i] && salt_hex[i + 1] && j < salt_len; i += 2, j++) {
            sscanf(salt_hex + i, "%2hhx", &salt[j]);
        }
        for (i = 0, j = 0; iv_hex[i] && iv_hex[i + 1] && j < iv_len; i += 2, j++) {
            sscanf(iv_hex + i, "%2hhx", &iv[j]);
        }

        unsigned char ciphertext[512];
        int cipher_len = 0;
        for (i = 0, j = 0; cipher_hex[i] && cipher_hex[i + 1] && j < 512; i += 2, j++) {
            sscanf(cipher_hex + i, "%2hhx", &ciphertext[j]);
            cipher_len++;
        }

        if (PKCS5_PBKDF2_HMAC(password, -1, salt, salt_len, iterations,
                              EVP_sha256(), key_len, key) != 1) {
            printf("Key derivation failed\n");
            return 1;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            printf("Context failed\n");
            return 1;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            printf("DecryptInit failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        unsigned char plain[512];
        int out1 = 0, out2 = 0;

        if (EVP_DecryptUpdate(ctx, plain, &out1, ciphertext, cipher_len) != 1) {
            printf("DecryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        if (EVP_DecryptFinal_ex(ctx, plain + out1, &out2) != 1) {
            printf("DecryptFinal failed (wrong password or data)\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        plain[out1 + out2] = '\0';
        printf("Decryption OK\n");
        printf("Result: %s\n", plain);

        EVP_CIPHER_CTX_free(ctx);
    }
    else {
        printf("Invalid choice\n");
        return 1;
    }

    return 0;
}