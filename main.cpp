#include <iostream>
#include "dhe.hpp"

int main() {
    try {
        DHE dhe;

        // Generate DH key pair and perform DH key exchange
        std::string public_key = dhe.get_public_key();
        std::cout << "Generated Public Key: " << public_key << std::endl;

        // Simulate receiving peer's public key (for testing, we use the same instance)
        std::string peer_public_key = dhe.get_public_key();

        // Generate shared key
        std::string shared_key = dhe.generate_shared_key(peer_public_key);
        std::cout << "Shared Key: " << shared_key << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
