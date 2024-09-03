#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <csignal>

#include "../Utility/Cryptography/RSAWrapper.h"

using namespace std;


#define DEFAULT_PORT 3030
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10


class Server {
    private:
        int port;
        int server_socket;
        struct sockaddr_in address;
        vector<thread> client_threads;
        static volatile bool server_running; 

        static void client_connection(int client_socket);
        static void signal_handler(int signal);

    public:
        Server(int port);
        void start();
        ~Server();

};


Server::Server(int port) {
    
    this->port = port;
    
    int opt = 1;

    // Register signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, Server::signal_handler);
    // Register signal handler for SIGTSTP (Ctrl+Z)
    signal(SIGTSTP, Server::signal_handler);

    // Create socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address and port
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the socket to the network address and port
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

}

volatile bool Server::server_running = true;

void Server::signal_handler(int signal) {
    if (signal == SIGINT) {
        cout << endl << "Forcing server shutdown..." << endl;
        exit(0);
    }
    else if (signal == SIGTSTP) {
        cout << endl << "Gently shutting down the server..." << endl;
        server_running = false;
    }
}

void Server::start() {
    // Start listening for incoming connections
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    cout << "Server ON and listening on port " << port << endl;
    cout << "To gently shut down the server, press Ctrl+Z" << endl;
    cout << "To force shutdown, press Ctrl+C" << endl << endl;


    // Server main loop
    while (server_running) {
        int client_socket;
        socklen_t addrlen = sizeof(address);

        // Accept new client connections
        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            if (server_running) {
                perror("Accept failed");
            }
            continue;
        }

        cout << "New connection accepted." << endl;
        client_threads.push_back(thread(client_connection, client_socket));
    }

    // Clean up threads
    for (auto &th : client_threads) {
        if (th.joinable()) {
            th.join();
        }
    }

}

Server::~Server() {
    close(server_socket);
    cout << "Server shutdown completed." << endl;
}


void Server::client_connection(int client_socket) {

    char buffer[BUFFER_SIZE];
    int bytes_read;

    // while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
    //     buffer[bytes_read] = '\0';
    //     cout << "Received: " << buffer << endl;
    //     send(client_socket, buffer, strlen(buffer), 0); // Echo back to client
    // }

    // 256 byte
    vector<unsigned char> encrypted_key(256);
    vector<unsigned char> iv(12);
    int32_t ciphertext_size;
    vector<unsigned char> ciphertext;
    vector<unsigned char> tag(16);

    bytes_read = read(client_socket, encrypted_key.data(), encrypted_key.size());
    bytes_read = read(client_socket, iv.data(), iv.size());
    bytes_read = read(client_socket, &ciphertext_size, sizeof(int32_t));
    ciphertext.resize(ciphertext_size);
    bytes_read = read(client_socket, ciphertext.data(), ciphertext.size());
    cout << "Ciphertext size: " << ciphertext.size() << endl;
    bytes_read = read(client_socket, tag.data(), tag.size());

    // Printing the tag as hex  
    cout << "Tag: ";
    for (int i = 0; i < tag.size(); i++) {
        cout << (int)tag[i];
    }
    cout << endl;


    // Printing the ciphertext
    cout << "Ciphertext: ";
    for (int i = 0; i < ciphertext.size(); i++) {
        cout << (int)ciphertext[i]<< " ";
    }
    cout << endl;

    RSAWrapper rsaWrapper("", "Server/Storage/Keys/server_privkey.pem");
    string decrypted = rsaWrapper.openEnvelope(ciphertext, encrypted_key, iv, tag);
    cout << "Decrypted: " << decrypted << endl;



    cout << "Client disconnected." << endl;
    close(client_socket);

}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    Server server(port);
    server.start();

    return 0;
}
