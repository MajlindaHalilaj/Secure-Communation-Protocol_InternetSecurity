#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <unistd.h>

#define PORT 12345
#define SERVER_IP "127.0.0.1"
#define CERT_FILE "client.crt"

SSL_CTX *createCTX() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in serv_addr;
    const char *client_msg = "TLS_RSA_WITH_AES_256_CBC_SHA256";

    // Initialize SSL context
    ctx = createCTX();

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address from text to binary form
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Check if the address conversion was successful
    if (serv_addr.sin_addr.s_addr == INADDR_NONE) {
    perror("Invalid address/ Address not supported");
    exit(EXIT_FAILURE);
    }


    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Send client hello message
    SSL_write(ssl, client_msg, strlen(client_msg));

    // Receive server response
    char server_msg[1024] = {0};
    SSL_read(ssl, server_msg, sizeof(server_msg));
    std::cout << "(Client) Message from server: " << server_msg << std::endl;

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Close socket
    close(sockfd);

    // Clean up SSL context
    SSL_CTX_free(ctx);

    return 0;
}
