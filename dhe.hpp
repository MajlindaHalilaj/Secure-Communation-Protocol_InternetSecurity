#ifndef DHE_HPP
#define DHE_HPP

#include <string>
#include <openssl/pem.h>
#include <openssl/err.h>

class DHE {
public:
    DHE();
    ~DHE();
    std::string get_public_key();
    std::string generate_shared_key(const std::string& peer_public_key_pem);

private:
    DH* private_key;
    DH* parameters;

    void handleOpenSSLError();
};

#endif // DHE_HPP
