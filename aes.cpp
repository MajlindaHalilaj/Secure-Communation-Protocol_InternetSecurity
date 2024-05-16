#include <openssl/aes.h>
#include <cstring>
#include <iostream>

class AES {
public:
    static unsigned char* aes256_encrypt(const unsigned char* key, const unsigned char* message, size_t message_len) {
        // Create AES encryption context
        AES_KEY aes_key;
        if (AES_set_encrypt_key(key, 256, &aes_key) != 0) {
            std::cerr << "Error setting AES encryption key" << std::endl;
            return nullptr;
        }

        // Allocate memory for ciphertext
        unsigned char* ciphertext = new unsigned char[message_len + AES_BLOCK_SIZE];
        if (ciphertext == nullptr) {
            std::cerr << "Error allocating memory for ciphertext" << std::endl;
            return nullptr;
        }

        // Encrypt the message using AES-256 ECB mode
        AES_ecb_encrypt(message, ciphertext, &aes_key, AES_ENCRYPT);
        return ciphertext;
    }
};
