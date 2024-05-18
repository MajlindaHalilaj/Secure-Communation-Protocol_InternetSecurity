#include <iostream>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>

class DHE {
public:
    DHE() : private_key(nullptr) {
        // Generate DHE parameters
        parameters = DH_new();
        if (!DH_generate_parameters_ex(parameters, 2048, DH_GENERATOR_2, nullptr)) {
            handleOpenSSLError();
        }

        // Generate private key
        private_key = DH_new();
        DH_generate_key(parameters);
        private_key = parameters;
    }








        return 0;
}