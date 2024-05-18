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
