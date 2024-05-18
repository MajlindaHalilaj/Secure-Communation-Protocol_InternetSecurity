#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

class SimplePKI {
public:
    SimplePKI() : private_key(nullptr), public_key(nullptr) {}

    ~SimplePKI() {
        if (private_key) RSA_free(private_key);
        if (public_key) RSA_free(public_key);
    }

void generate_key_pair() {
        int bits = 2048;
        unsigned long e = RSA_F4;

        BIGNUM* bn = BN_new();
        BN_set_word(bn, e);

 private_key = RSA_new();
        if (!RSA_generate_key_ex(private_key, bits, bn, nullptr)) {
            handleOpenSSLError();
        }

        // Extract the public key from the private key
        BIO* pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(pub, private_key);
        public_key = PEM_read_bio_RSAPublicKey(pub, nullptr, nullptr, nullptr);

        BN_free(bn);
        BIO_free(pub);
    }

std::string sign(const std::string& message) {
        if (!private_key) {
            throw std::runtime_error("Private key not generated");
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)message.c_str(), message.size(), hash);

unsigned char* sig = new unsigned char[RSA_size(private_key)];
        unsigned int sig_len;

        if (!RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, private_key)) {
            delete[] sig;
            handleOpenSSLError();
        }

        std::string signature((char*)sig, sig_len);
        delete[] sig;
        return signature;
    }

};

int main() {
    SimplePKI pki;
    pki.generate_key_pair();

    std::string message = "Hello, world!";
    std::string signature = pki.sign(message);

    if (pki.verify(message, signature)) {
        std::cout << "Signature is valid" << std::endl;
    } else {
        std::cout << "Signature is invalid" << std::endl;
    }

    return 0;
}
