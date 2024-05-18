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


}