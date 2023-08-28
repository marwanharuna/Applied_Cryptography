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
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    const char *hello = "Hello from server";
    char buffer[1024] = {0};

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }

    // Attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return -1;
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return -1;
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept");
        return -1;
    }

    valread = read(new_socket, buffer, 1024);
    std::cout << buffer << std::endl;
    send(new_socket, hello, strlen(hello), 0);
    std::cout << "Hello message sent" << std::endl;

    //unsigned char key;

     authenticate(new_socket);

    // Prompt user to close the connection
    std::cout << "Press any key to close the connection...";
    std::cin.ignore();
    
    // Close the connection
    close(new_socket);

    return 0;
}
