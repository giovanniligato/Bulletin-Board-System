#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h> // For cryptographic operations
#include <openssl/rand.h> // For secure random number generation
#include <signal.h>
#include <mutex>

#include "../Utility/Cryptography/Randomness.h"
#include "../Utility/Cryptography/RSAWrapper.h"
#include "../Utility/Cryptography/AESGCMWrapper.h"
#include "../Utility/Cryptography/DHWrapper.h"
#include "../Utility/Cryptography/Hash.h"
#include "../Packets/GeneralPacket.h"
#include "../FileSystem/User.h"
#include "../FileSystem/BulletinBoard.h"


using namespace std;

#define DEFAULT_PORT 3030
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 5

class Server {
public:
    Server(int port);
    void start();
    ~Server();

private:
    int server_socket;
    struct sockaddr_in address;
    vector<thread> client_threads;

    static volatile bool server_running; 

    static BulletinBoard bulletinBoard;

    static void clientHandler(int client_socket);
    static void signalHandler(int signal);
    static void performKeyExchange(int client_socket, vector<unsigned char>& sessionKey);
    static void processClientRequests(int client_socket, const vector<unsigned char>& sessionKey);
    
    static void registerUser(int client_socket, const vector<unsigned char>& sessionKey, GeneralPacket receivedPacket);
    static void loginUser(int client_socket, const vector<unsigned char>& sessionKey, vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket);

    static void listMessages(int client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket);
    static void getMessage(int client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket);
    static void addMessage(int& client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket);


    // Helper functions for encryption and decryption
    static string decryptMessage(const vector<unsigned char>& ciphertext, const vector<unsigned char>& sessionKey);
    static vector<unsigned char> encryptMessage(const string& plaintext, const vector<unsigned char>& sessionKey);
};

volatile bool Server::server_running = true;
BulletinBoard Server::bulletinBoard("Server/Storage/BulletinBoard");

Server::Server(int port) {
    int opt = 1;

    // Register signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, Server::signalHandler);
    // Register signal handler for SIGTSTP (Ctrl+Z)
    signal(SIGTSTP, Server::signalHandler);

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

void Server::signalHandler(int signal) {
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

    cout << "Server ON and listening on port " << ntohs(address.sin_port) << endl;
    cout << "To gently shut down the server, press Ctrl+Z" << endl;
    cout << "To force shutdown, press Ctrl+C" << endl << endl;

    // Server main loop
    while (server_running) {
        int client_socket;
        socklen_t addrlen = sizeof(address);

        // Accept new client connections
        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, &addrlen)) < 0) {
            if (server_running) {
                perror("Accept failed");
            }
            continue;
        }

        cout << "New connection accepted." << endl;

        // Create a new thread to handle the client
        client_threads.push_back(thread(Server::clientHandler, client_socket));
    }

    // Clean up threads
    for (auto &th : client_threads) {
        if (th.joinable()) {
            th.join();
        }
    }
}

void Server::clientHandler(int client_socket) {
    
    vector<unsigned char> sessionKey;

    // Step 1: Perform key exchange with the client to establish a secure session
    performKeyExchange(client_socket, sessionKey);

    // Step 2: Process client requests using the established session key
    processClientRequests(client_socket, sessionKey);

    // Close the client socket after the session ends
    close(client_socket);
    cout << "Client disconnected." << endl;
}

void Server::performKeyExchange(int client_socket, vector<unsigned char>& sessionKey) {

    try {

        // Diffie-Hellman key exchange
        DHWrapper dhWrapper(1024);
        
        vector<unsigned char> authKey;
        // As we are using AES128-GCM for symmetric encryption, we need a 128-bit key (16 bytes)
        sessionKey = dhWrapper.serverKeyExchange(client_socket, authKey, true, 16);

    }
    catch (const exception& ex) {
        cerr << "Error in connectToServer(): " << ex.what() << endl;
    }

}

void Server::processClientRequests(int client_socket, const vector<unsigned char>& sessionKey) {

    vector<unsigned char> postLoginSessionKey;

    try{

        while(client_socket > 0){
            GeneralPacket receivedPacket = postLoginSessionKey.empty()
                                         ? GeneralPacket::receive(client_socket, sessionKey)
                                         : GeneralPacket::receive(client_socket, postLoginSessionKey);


            switch(receivedPacket.getType()){
                case T_REGISTRATION:
                    if(!postLoginSessionKey.empty()){
                        cout << "Cannot register when user is logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    registerUser(client_socket, sessionKey, receivedPacket);
                    break;
                case T_LOGIN:
                    if(!postLoginSessionKey.empty()){
                        cout << "User already logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    loginUser(client_socket, sessionKey, postLoginSessionKey, receivedPacket);
                    break;
                case T_LIST:
                    if(postLoginSessionKey.empty()){
                        cout << "Cannot list when user is not logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    cout << "Received LIST request." << endl;
                    listMessages(client_socket, postLoginSessionKey, receivedPacket);
                    break;
                case T_GET:
                    if(postLoginSessionKey.empty()){
                        cout << "Cannot get when user is not logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    cout << "Received GET request." << endl;
                    getMessage(client_socket, postLoginSessionKey, receivedPacket);
                    break;
                case T_ADD:
                    if(postLoginSessionKey.empty()){
                        cout << "Cannot add when user is not logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    cout << "Received ADD request." << endl;
                    addMessage(client_socket, postLoginSessionKey, receivedPacket);
                    break;
                case T_LOGOUT:
                    if(postLoginSessionKey.empty()){
                        cout << "Cannot logout when user is not logged in." << endl;
                        cout << "Closing connection..." << endl;
                        close(client_socket);
                        client_socket = -1;
                        break;
                    }
                    cout << "Received LOGOUT request." << endl;
                    postLoginSessionKey.clear();
                    break;
                default:
                    cout << "Invalid packet type received." << endl;
                    cout << "Closing connection..." << endl;
                    close(client_socket);
                    client_socket = -1;
                    break;
            }

        }

    }
    catch(const exception& ex){
        cerr << "Error in processClientRequests(): " << ex.what() << endl;
    }

    
    
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';

        // Step 3: Decrypt the incoming message using the sessionKey
        vector<unsigned char> ciphertext(buffer, buffer + bytes_read);
        string decryptedMessage = decryptMessage(ciphertext, sessionKey);

        // Process the decrypted message (e.g., handle commands like LIST, GET, ADD)
        // TO DO: Implement the logic to handle different client requests

        // Example: Echo the message back to the client (encrypted)
        string response = "Message received: " + decryptedMessage;
        vector<unsigned char> encryptedResponse = encryptMessage(response, sessionKey);
        send(client_socket, encryptedResponse.data(), encryptedResponse.size(), 0);
    }
}

void Server::registerUser(int client_socket, const vector<unsigned char>& sessionKey, GeneralPacket receivedPacket) {
    
    try{

        vector<unsigned char> nonce = receivedPacket.getAAD();
        vector<unsigned char> payload = receivedPacket.getPayload();

        // Extract the email, nickname, and password from the payload
        // 1 Byte for the email length, email, 1 Byte for the nickname length, nickname, 1 Byte for the password length, password
        uint8_t email_length = payload[0];
        string email(payload.begin() + 1, payload.begin() + 1 + email_length);

        uint8_t nickname_length = payload[1 + email_length];
        string nickname(payload.begin() + 1 + email_length + 1, payload.begin() + 1 + email_length + 1 + nickname_length);

        uint8_t password_length = payload[1 + email_length + 1 + nickname_length];
        string password(payload.begin() + 1 + email_length + 1 + nickname_length + 1, payload.begin() + 1 + email_length + 1 + nickname_length + 1 + password_length);

        cout << "Received registration request:" << endl;
        cout << "Email: " << email << endl;
        cout << "nickname: " << nickname << endl;
        cout << "Password: " << password << endl;

        
        User newUser(email, nickname, password);
        // At this point, the server has to check if the nickname is already in use
        // If the nickname is not in use, the server can register the user

        payload.clear();

        if(!newUser.checkExistence()){
            // The user does not exist, so we can register the user
            // but before that, the server has to send a challenge
            // to the email address specified by the user
            vector<unsigned char> challenge = newUser.sendChallenge();

            // Sending the response to the client
            GeneralPacket responsePacket(nonce, T_OK, payload);
            // Send securely to the server
            responsePacket.send(client_socket, sessionKey);

            // Now waiting for the client to send the response to the challenge
            GeneralPacket challengePacket = GeneralPacket::receive(client_socket, sessionKey);

            if(challengePacket.getPayload() != challenge){
                cout << "Challenge response incorrect." << endl;
                
                responsePacket.setType(T_KO);
                responsePacket.send(client_socket, sessionKey);

                // Delete the challenge
                newUser.deleteChallenge();
                return;
            }

            // User has successfully responded to the challenge
            // Now we can register the user
            newUser.saveUser();

            cout << "User registered successfully." << endl;
           
            // Send securely to the server
            responsePacket.send(client_socket, sessionKey);

            // Delete the challenge
            newUser.deleteChallenge();
        }
        else{
            cout << "User already exists." << endl;

            GeneralPacket responsePacket(nonce, T_KO, payload);
            // Send securely to the server
            responsePacket.send(client_socket, sessionKey);
            return;
        }

    }
    catch(const exception& ex){
        cerr << "Error in registerUser(): " << ex.what() << endl;
    }
    
    // TO DO: Implement user registration logic
    // For now, just echo the received packet back to the client
    // receivedPacket.send(client_socket);
}

void Server::loginUser(int client_socket, const vector<unsigned char>& sessionKey, vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket) {
    
    try{

        vector<unsigned char> nonce = receivedPacket.getAAD();
        vector<unsigned char> payload = receivedPacket.getPayload();

        // Extract the nickname and password from the payload
        // 1 Byte for the nickname length, nickname, 1 Byte for the password length, password
        uint8_t nickname_length = payload[0];
        string nickname(payload.begin() + 1, payload.begin() + 1 + nickname_length);

        uint8_t password_length = payload[1 + nickname_length];
        string password(payload.begin() + 1 + nickname_length + 1, payload.begin() + 1 + nickname_length + 1 + password_length);

        cout << "Received login request:" << endl;
        cout << "nickname: " << nickname << endl;
        cout << "Password: " << password << endl;

        User user(nickname, password);

        payload.clear();

        if(user.checkExistence() && user.checkPassword()){
            cout << "User logged in successfully." << endl;

            GeneralPacket responsePacket(nonce, T_OK, payload);
            // Send securely to the server
            responsePacket.send(client_socket, sessionKey);

            // Begin a new instance of the DH key exchange
            DHWrapper dhWrapper(1024);
            postLoginSessionKey = dhWrapper.serverKeyExchange(client_socket, sessionKey, false, 16);

        }
        else{
            cout << "User login failed." << endl;

            GeneralPacket responsePacket(nonce, T_KO, payload);
            // Send securely to the server
            responsePacket.send(client_socket, sessionKey);
        }

    }
    catch(const exception& ex){
        cerr << "Error in loginUser(): " << ex.what() << endl;
    }

    // TO DO: Implement user login logic
    // For now, just echo the received packet back to the client
    // receivedPacket.send(client_socket);
}

void Server::listMessages(int client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket) {
    
    try{

        vector<unsigned char> nonce = receivedPacket.getAAD();
        vector<unsigned char> payload = receivedPacket.getPayload();


    }
    catch(const exception& ex){
        cerr << "Error in listMessages(): " << ex.what() << endl;
    }

    // TO DO: Implement list messages logic
    // For now, just echo the received packet back to the client
    // receivedPacket.send(client_socket);
}

void Server::getMessage(int client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket) {
    
    try{

        vector<unsigned char> nonce = receivedPacket.getAAD();
        vector<unsigned char> payload = receivedPacket.getPayload();
    }
    catch(const exception& ex){
        cerr << "Error in getMessage(): " << ex.what() << endl;
    }

    // TO DO: Implement get message logic
    // For now, just echo the received packet back to the client
    // receivedPacket.send(client_socket);

}

void Server::addMessage(int& client_socket, const vector<unsigned char>& postLoginSessionKey, GeneralPacket receivedPacket) {
    
    try{
        vector<unsigned char> clientNonce = receivedPacket.getAAD();
        
        // Sending back to the client a server nonce to be sure
        // that the request of adding a message is not a replay attack
        vector<unsigned char> nonce = generateRandomBytes(16);

        // AAD is the concatenation of the client nonce and the server nonce
        vector<unsigned char> aad(clientNonce);
        aad.insert(aad.end(), nonce.begin(), nonce.end());

        vector<unsigned char> payload;

        // Construct the response packet
        GeneralPacket responsePacket(aad, T_OK, payload);
        // Send securely to the client
        responsePacket.send(client_socket, postLoginSessionKey);

        // Receive the message from the client
        GeneralPacket messagePacket = GeneralPacket::receive(client_socket, postLoginSessionKey);
        // Check if the message is not a replay attack
        if(messagePacket.getAAD() != aad){
            cout << "Replay attack detected." << endl;
            cout << "Closing connection..." << endl;
            close(client_socket);
            client_socket = -1;
            return;
        }

        vector<unsigned char> messagePayload = messagePacket.getPayload();
        // Payload is the concatenation of the title, author, and body
        // 1 Byte for the title length, title, 1 Byte for the author length, author, 1 Byte for the body length, body

        uint8_t title_length = messagePayload[0];
        string title(messagePayload.begin() + 1, messagePayload.begin() + 1 + title_length);

        uint8_t author_length = messagePayload[1 + title_length];
        string author(messagePayload.begin() + 1 + title_length + 1, messagePayload.begin() + 1 + title_length + 1 + author_length);

        uint8_t body_length = messagePayload[1 + title_length + 1 + author_length];
        string body(messagePayload.begin() + 1 + title_length + 1 + author_length + 1, messagePayload.begin() + 1 + title_length + 1 + author_length + 1 + body_length);

        cout << "Received message:" << endl;
        cout << "Title: " << title << endl;
        cout << "Author: " << author << endl;
        cout << "Body: " << body << endl;


        try{
            cout<<"Adding message to the Bulletin Board..."<<endl;
            // Now we can save the message in the Bulletin Board
            bulletinBoard.add(title, author, body);
            cout << "Message added successfully." << endl;
        }
        catch(const exception& ex){
            cerr << "Error in addMessage(): " << ex.what() << endl;
            responsePacket.setType(T_KO);
        }

        // Send the response to the client
        responsePacket.send(client_socket, postLoginSessionKey);
        
    }
    catch(const exception& ex){
        cerr << "Error in addMessage(): " << ex.what() << endl;
    }

    // TO DO: Implement add message logic
    // For now, just echo the received packet back to the client
    // receivedPacket.send(client_socket);
}



string Server::decryptMessage(const vector<unsigned char>& ciphertext, const vector<unsigned char>& sessionKey) {
    // TO DO: Implement decryption using sessionKey
    // For now, just return the plaintext as a placeholder
    return string(ciphertext.begin(), ciphertext.end());
}

vector<unsigned char> Server::encryptMessage(const string& plaintext, const vector<unsigned char>& sessionKey) {
    // TO DO: Implement encryption using sessionKey
    // For now, just return the plaintext as a vector of unsigned char as a placeholder
    return vector<unsigned char>(plaintext.begin(), plaintext.end());
}

Server::~Server() {
    close(server_socket);
    cout << "Server shutdown completed." << endl;
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
