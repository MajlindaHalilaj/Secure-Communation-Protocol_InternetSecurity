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


 ~DHE() {
        if (private_key) DH_free(private_key);
    }

 std::string get_public_key() {
        // Get the public key to send to the other party
        BIO* bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_DHparams(bio, parameters)) {
            BIO_free(bio);
            handleOpenSSLError();
        }

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::string public_key(bufferPtr->data, bufferPtr->length);
        BIO_free(bio);
        return public_key;
    }






        return 0;
}
