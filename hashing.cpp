#include <openssl/sha.h>
#include <cstring>
#include <iostream>

class SHA {
public:
    static unsigned char* sha256(const char* message) {
        unsigned char* digest = new unsigned char[SHA256_DIGEST_LENGTH];
        if (!digest) {
            std::cerr << "Error allocating memory for digest" << std::endl;
            return nullptr;
        }

        // Compute the SHA-256 hash of the message
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, message, strlen(message));
        SHA256_Final(digest, &ctx);

        return digest;
    }
};
