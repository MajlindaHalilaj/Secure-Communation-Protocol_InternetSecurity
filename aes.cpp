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
    
    static unsigned char* aes256_decrypt(const unsigned char* key, const unsigned char* ciphertext, size_t ciphertext_len) {
        // Create AES decryption context
        AES_KEY aes_key;
        if (AES_set_decrypt_key(key, 256, &aes_key) != 0) {
            std::cerr << "Error setting AES decryption key" << std::endl;
            return nullptr;
        }

        // Allocate memory for decrypted message
        unsigned char* decrypted_message = new unsigned char[ciphertext_len];
        if (decrypted_message == nullptr) {
            std::cerr << "Error allocating memory for decrypted message" << std::endl;
            return nullptr;
        }

        // Decrypt the ciphertext using AES-256 ECB mode
        AES_ecb_encrypt(ciphertext, decrypted_message, &aes_key, AES_DECRYPT);
        return decrypted_message;
    }
};
