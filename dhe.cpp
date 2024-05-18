#include "dhe.hpp"
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>

DHE::DHE() : private_key(nullptr) {
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

DHE::~DHE() {
    if (private_key) DH_free(private_key);
}

std::string DHE::get_public_key() {
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

std::string DHE::generate_shared_key(const std::string& peer_public_key_pem) {
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

    std::string shared_key_str(reinterpret_cast<char*>(shared_key), shared_key_len);
    DH_free(peer_dh);
    return shared_key_str;
}

void DHE::handleOpenSSLError() {
    char* err = ERR_error_string(ERR_get_error(), nullptr);
    std::cerr << "OpenSSL error: " << err << std::endl;
    throw std::runtime_error("OpenSSL error occurred");
}
