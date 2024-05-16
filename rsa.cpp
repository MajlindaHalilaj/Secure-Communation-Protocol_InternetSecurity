#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>

class RSA {
public:
    static std::pair<RSA*, RSA*> generate_rsa_key_pair() {
        RSA* private_key = RSA_new();
        RSA* public_key = RSA_new();

        // Generate RSA key pair
        BIGNUM* exponent = BN_new();
        BN_set_word(exponent, RSA_F4); // Public exponent (65537)
        if (!RSA_generate_key_ex(private_key, 2048, exponent, NULL)) {
            std::cerr << "Error generating RSA key pair" << std::endl;
            return std::make_pair(nullptr, nullptr);
        }
        RSA* tmp = private_key;
        if (!RSA_check_key(tmp)) {
            std::cerr << "Error checking RSA private key" << std::endl;
            return std::make_pair(nullptr, nullptr);
        }
        RSA* pub = RSAPublicKey_dup(private_key);
        if (!pub) {
            std::cerr << "Error extracting RSA public key" << std::endl;
            return std::make_pair(nullptr, nullptr);
        }
        return std::make_pair(private_key, pub);
    }

    static unsigned char* rsa_encrypt(RSA* public_key, const unsigned char* message, size_t message_len, size_t* encrypted_len) {
        // Allocate memory for ciphertext
        unsigned char* ciphertext = new unsigned char[RSA_size(public_key)];
        if (!ciphertext) {
            std::cerr << "Error allocating memory for ciphertext" << std::endl;
            return nullptr;
        }

   // Encrypt the message using RSA public key
        *encrypted_len = RSA_public_encrypt(message_len, message, ciphertext, public_key, RSA_PKCS1_OAEP_PADDING);
        if (*encrypted_len == -1) {
            std::cerr << "Error encrypting message" << std::endl;
            delete[] ciphertext;
            return nullptr;
        }
        return ciphertext;
    }

    static unsigned char* rsa_decrypt(RSA* private_key, const unsigned char* ciphertext, size_t ciphertext_len, size_t* decrypted_len) {
        // Allocate memory for decrypted message
        unsigned char* decrypted_message = new unsigned char[ciphertext_len];
        if (!decrypted_message) {
            std::cerr << "Error allocating memory for decrypted message" << std::endl;
            return nullptr;
        }

  // Decrypt the ciphertext using RSA private key
        *decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted_message, private_key, RSA_PKCS1_OAEP_PADDING);
        if (*decrypted_len == -1) {
            std::cerr << "Error decrypting ciphertext" << std::endl;
            delete[] decrypted_message;
            return nullptr;
        }
        return decrypted_message;

    }
};
