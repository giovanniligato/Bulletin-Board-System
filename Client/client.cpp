#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>

#include "../Utility/Cryptography/Randomness.h"
#include "../Utility/Cryptography/RSAWrapper.h"
#include "../Utility/Cryptography/AESGCMWrapper.h"
#include "../Utility/Cryptography/DHWrapper.h"
#include "../Utility/Cryptography/Hash.h"

using namespace std;

#define DEFAULT_PORT 3030
#define BUFFER_SIZE 1024
#define SERVER_ADDRESS "127.0.0.1" // Localhost


class Client {
public:
    Client(const string& serverAddress, int port);
    ~Client();
    
    void run();

private:
    int port;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    bool isLoggedIn = false;

    void connectToServer();
    void closeConnection();
    void registrationPhase();
    void login();
    void logout();
    void postLoginMenu();
    void listMessages(int n);
    void getMessage(int mid);
    void addMessage(const string& title, const string& author, const string& body);
};

Client::Client(const string& serverAddress, int port) : port(port) {
    
    // Initialize socket and server address
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        throw runtime_error("Socket creation error");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, serverAddress.c_str(), &serv_addr.sin_addr) <= 0) {
        throw runtime_error("Invalid address or Address not supported");
    }
}

Client::~Client() {
    closeConnection();
}

void Client::connectToServer() {

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        throw runtime_error("Connection failed");
    }
    cout << "Connected to server at " << SERVER_ADDRESS << ":" << port << endl;

    // Basic connection established.

    // Now there is the need to implement the "secure connection".
    try{
        // Generate a random 16 byte ephemeral key, used for just for authentication purposes
        vector<unsigned char> authentication_key =  generateRandomBytes(16);

        // Encrypt the authentication key using the server's public key
        RSAWrapper rsaWrapper("Client/Storage/Keys/server_pubkey.pem", "");
        vector<unsigned char> encrypted_authentication_key = rsaWrapper.encrypt(authentication_key, KeyType::Public);

        // Generate the public key for the Diffie-Hellman key exchange
        DHWrapper dhWrapper(1024);
        vector<unsigned char> clientDH_public_key = dhWrapper.getPublicKey();

        // Generate a nonce to prevent replay attacks
        vector<unsigned char> nonce = generateRandomBytes(16);

        vector<unsigned char> iv;
        vector<unsigned char> tag;
        vector<unsigned char> aad;

        vector<unsigned char> plaintext;
        vector<unsigned char> ciphertext;


        // Insert into the aad the clientDH_public_key and the nonce
        aad.insert(aad.end(), clientDH_public_key.begin(), clientDH_public_key.end());
        aad.insert(aad.end(), nonce.begin(), nonce.end());

        // Compute the authentication tag for the message clientDH_public_key || nonce
        AESGCMWrapper::encrypt(authentication_key, plaintext, ciphertext, iv, tag, aad);

        // Sending all to the server

        // 256 Bytes
        send(sock, encrypted_authentication_key.data(), encrypted_authentication_key.size(), 0);

        // 12 Bytes
        send(sock, iv.data(), iv.size(), 0);

        // 670 Bytes
        send(sock, aad.data(), aad.size(), 0);

        // 16 Bytes
        send(sock, tag.data(), tag.size(), 0);

        // Receiving the server's public key and the nonce
        
        // Receiving the IV (12 bytes)
        if (recv(sock, iv.data(), iv.size(), 0) < 0) {
            throw runtime_error("Failed to receive the IV.");
        }

        // Receiving the AAD (670 bytes)
        if (recv(sock, aad.data(), aad.size(), 0) < 0) {
            throw runtime_error("Failed to receive the AAD.");
        }

        // Receiving the tag (16 bytes)
        if (recv(sock, tag.data(), tag.size(), 0) < 0) {
            throw runtime_error("Failed to receive the tag.");
        }

        // Check the tag for the AAD
        plaintext = AESGCMWrapper::decrypt(authentication_key, ciphertext, iv, tag, aad);

        // Extract the server's public key and nonce from the AAD (last 16 bytes are the nonce)
        vector<unsigned char> serverDH_public_key(aad.begin(), aad.end() - 16);
        vector<unsigned char> received_nonce(aad.end() - 16, aad.end());

        // Check if the nonce is the same as the one sent
        if (nonce != received_nonce) {
            throw runtime_error("Nonce mismatch.");
        }

        // Load the server's public key
        dhWrapper.loadPeerPublicKey(serverDH_public_key);

        // Compute the shared secret
        vector<unsigned char> DH_shared_secret = dhWrapper.computeSharedSecret();

        // Before using the shared secret as the session key, it is a good practice to hash it
        vector<unsigned char> sessionKey = Hash::computeSHA256(DH_shared_secret);

        cout << "Session key Hex: "<< Hash::toHexString(sessionKey) << endl;   

    }
    catch (const exception& ex) {
        cerr << "Error in connectToServer(): " << ex.what() << endl;
        exit(-1);
    }


}

void Client::closeConnection() {
    close(sock);
    cout << "Connection closed." << endl;
}

void Client::registrationPhase() {
    while (!isLoggedIn) {
        cout << "\n--- Registration Phase ---" << endl;
        cout << "1. Register" << endl;
        cout << "2. Login" << endl;
        cout << "3. Exit" << endl;
        cout << "Choose an option: ";
        
        int choice;
        cin >> choice;
        cin.ignore(); // Clear the input buffer

        switch (choice) {
            case 1:
                // Implement registration logic here
                cout << "Registration is currently not implemented." << endl;
                break;
            case 2:
                login();
                break;
            case 3:
                closeConnection();
                exit(0);
            default:
                cout << "Invalid option. Please try again." << endl;
                break;
        }
    }
}

void Client::login() {
    string username, password;
    cout << "Enter username: ";
    getline(cin, username);
    cout << "Enter password: ";
    getline(cin, password);

    // Send login credentials to the server
    string loginMessage = "LOGIN " + username + " " + password;
    send(sock, loginMessage.c_str(), loginMessage.length(), 0);

    // Receive the response from the server
    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        string response(buffer);
        if (response == "OK") {
            isLoggedIn = true;
            cout << "Login successful." << endl;
            postLoginMenu();
        } else {
            cout << "Login failed: " << response << endl;
        }
    }
}

void Client::logout() {
    isLoggedIn = false;
    cout << "Logged out successfully." << endl;
}

void Client::postLoginMenu() {
    while (isLoggedIn) {
        cout << "\n--- BBS Menu ---" << endl;
        cout << "1. List Messages" << endl;
        cout << "2. Get Message" << endl;
        cout << "3. Add Message" << endl;
        cout << "4. Logout" << endl;
        cout << "Choose an option: ";
        
        int choice;
        cin >> choice;
        cin.ignore(); // Clear the input buffer

        switch (choice) {
            case 1: {
                int n;
                cout << "Enter number of messages to list: ";
                cin >> n;
                cin.ignore();
                listMessages(n);
                break;
            }
            case 2: {
                int mid;
                cout << "Enter message ID to get: ";
                cin >> mid;
                cin.ignore();
                getMessage(mid);
                break;
            }
            case 3: {
                string title, author, body;
                cout << "Enter title: ";
                getline(cin, title);
                cout << "Enter author: ";
                getline(cin, author);
                cout << "Enter body: ";
                getline(cin, body);
                addMessage(title, author, body);
                break;
            }
            case 4:
                logout();
                break;
            default:
                cout << "Invalid option. Please try again." << endl;
                break;
        }
    }
}

void Client::listMessages(int n) {
    string listCommand = "LIST " + to_string(n);
    send(sock, listCommand.c_str(), listCommand.length(), 0);

    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "Messages:\n" << buffer << endl;
    }
}

void Client::getMessage(int mid) {
    string getCommand = "GET " + to_string(mid);
    send(sock, getCommand.c_str(), getCommand.length(), 0);

    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "Message:\n" << buffer << endl;
    }
}

void Client::addMessage(const string& title, const string& author, const string& body) {
    string addCommand = "ADD " + title + " " + author + " " + body;
    send(sock, addCommand.c_str(), addCommand.length(), 0);

    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "Server response:\n" << buffer << endl;
    }
}

void Client::run() {
    connectToServer();
    registrationPhase();
}

int main(int argc, char *argv[]) {

    int PORT = DEFAULT_PORT;

    if (argc > 1) {
        PORT = stoi(argv[1]);
    }

    try {
        Client client(SERVER_ADDRESS, PORT);
        client.run();
    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return -1;
    }

    return 0;
}
