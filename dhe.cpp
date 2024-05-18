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


std::string generate_shared_key(const std::string& peer_public_key_pem) {
        // Load peer's public key
        BIO* bio = BIO_new_mem_buf(peer_public_key_pem.data(), peer_public_key_pem.size());
        DH* peer_dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);


if (!peer_dh) {
            handleOpenSSLError();
        }

        const BIGNUM* peer_pub_key = DH_get0_pub_key(peer_dh);

        // Generate shared key
        unsigned char shared_key[DH_size(private_key)];
        int shared_key_len = DH_compute_key(shared_key, peer_pub_key, private_key);
        if (shared_key_len == -1) {
            DH_free(peer_dh);
            handleOpenSSLError();
        }



int main() {
    DHE dhe;
    std::string public_key = dhe.get_public_key();
    std::cout << "Public Key: " << public_key << std::endl;

    // Simulate receiving peer's public key (in practice, this would come from the other party)
    DHE peer_dhe;
    std::string peer_public_key = peer_dhe.get_public_key();

    std::string shared_key = dhe.generate_shared_key(peer_public_key);
    std::cout << "Shared Key: " << shared_key << std::endl;


        return 0;
}
