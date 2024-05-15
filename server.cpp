#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <cstring>
#include <winsock2.h>

#define PORT 12345
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

SSL_CTX *createCTX() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd, newsockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    const char *client_msg;
    const char *server_msg = "TLS_RSA_WITH_AES_256_CBC_SHA256";

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
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(sockfd, 1) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Accept incoming connection
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, newsockfd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Receive client hello message
    char client_msg_buf[1024] = {0};
    SSL_read(ssl, client_msg_buf, sizeof(client_msg_buf));
    client_msg = client_msg_buf;
    std::cout << "(Server) Message from client: " << client_msg << std::endl;

    // Send server hello message
    SSL_write(ssl, server_msg, strlen(server_msg));

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Close sockets
    close(newsockfd);
    close(sockfd);

    // Clean up SSL context
    SSL_CTX_free(ctx);

    return 0;
}
