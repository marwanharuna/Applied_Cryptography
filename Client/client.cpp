#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <sys/types.h>
#include <dirent.h>
#include "utils/authenticate.h"

#define PORT 8080


int main(int argc, char const *argv[]) {
    
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    const char *hello = "Hello from client";
    char buffer[1024] = {0};

    // Socket creation
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cout << "Invalid address/Address not supported" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cout << "Connection failed" << std::endl;
        return -1;
    }

    // Send a message to the server
    send(sock, hello, strlen(hello), 0);
    std::cout << "Hello message sent" << std::endl;

    // Receive a response from the server
    valread = read(sock, buffer, 1024);
    std::cout << buffer << std::endl;

       // unsigned char key;

     authenticate(sock);

    // Prompt user to close the connection
    std::cout << "Press any key to close the connection...";
    std::cin.ignore();

    // Close the connection
    close(sock);

    return 0;
}
