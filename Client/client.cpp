#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <termios.h>

#include "../Utility/Cryptography/Randomness.h"
#include "../Utility/Cryptography/RSAWrapper.h"
#include "../Utility/Cryptography/AESGCMWrapper.h"
#include "../Utility/Cryptography/DHWrapper.h"
#include "../Utility/Cryptography/Hash.h"
#include "../Packets/GeneralPacket.h"

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

    vector<unsigned char> sessionKey;
    vector<unsigned char> postLoginSessionKey;

    string loggedInNickname;


    char buffer[BUFFER_SIZE] = {0};
    bool isLoggedIn = false;

    void connectToServer();
    void closeConnection();
    void registrationPhase();
    void registerUser();
    string getPassword();
    void login();
    void logout();
    void postLoginMenu();
    void listMessages();
    void getMessage();
    void addMessage();
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

        // Diffie-Hellman key exchange
        DHWrapper dhWrapper(1024);
        // As we are using AES128-GCM for symmetric encryption, we need a 128-bit key (16 bytes)
        sessionKey = dhWrapper.clientKeyExchange(sock, authentication_key, true, 16);

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
                registerUser();
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

string Client::getPassword() {
    termios oldt, newt;
    string password;

    // Get current terminal attributes
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    
    // Disable echo
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    cout << "Enter password: ";
    getline(cin, password);

    // Restore old terminal attributes
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    cout << endl;  // Move to the next line

    return password;
}

void Client::registerUser() {

    try {

        string email, nickname, password;
        cout << "Enter email: ";
        getline(cin, email);
        cout << "Enter nickname: ";
        getline(cin, nickname);
        password = getPassword();

        // Send registration credentials to the server
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Insert the email, nickname, and password into the payload
        // 1 Byte for the email length, email, 1 Byte for the nickname length, nickname, 1 Byte for the password length, password
        payload.push_back(email.length());
        payload.insert(payload.end(), email.begin(), email.end());
        payload.push_back(nickname.length());
        payload.insert(payload.end(), nickname.begin(), nickname.end());
        payload.push_back(password.length());
        payload.insert(payload.end(), password.begin(), password.end());

        // Construct the packet
        GeneralPacket registrationPacket(nonce, T_REGISTRATION, payload);
        // Send securely to the server
        registrationPacket.send(sock, sessionKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, sessionKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            cout << "Challenge sent to your email." << endl;
            cout << "Please check your email and enter the challenge code: ";
            uint32_t challenge;
            cin >> challenge;
            cin.ignore();

            // Send the challenge to the server
            payload.clear();

            // Insert the challenge into the payload
            vector<unsigned char> challenge_bytes = {static_cast<unsigned char>((challenge >> 24) & 0xFF), 
                                                     static_cast<unsigned char>((challenge >> 16) & 0xFF),
                                                     static_cast<unsigned char>((challenge >> 8) & 0xFF),
                                                     static_cast<unsigned char>(challenge & 0xFF)};
            payload.insert(payload.end(), challenge_bytes.begin(), challenge_bytes.end());
            
            registrationPacket.setPayload(payload);

            // Send securely to the server
            registrationPacket.send(sock, sessionKey);

            // Receive the response from the server
            responsePacket = GeneralPacket::receive(sock, sessionKey);

            if(responsePacket.getAAD() != nonce) {
                cout << "Nonce mismatch." << endl;
                exit(-1);
            }

            if(responsePacket.getType() == T_OK) {
                cout << "Registration successful." << endl;
                return;
            }
            else if(responsePacket.getType() == T_KO) {
                cout << "Challenge code is incorrect. User registration failed." << endl;
                return;
            }
            else {
                cout << "Not expected response type." << endl;
                exit(-1);
            }
            
        } 
        else if(responsePacket.getType() == T_KO) {
            cout << "Nickname already exists." << endl;
            return;
        }
        else {
            cout << "Not expected response type." << endl;
            exit(-1);
        }




        string registerMessage = "REGISTER " + nickname + " " + password;
        send(sock, registerMessage.c_str(), registerMessage.length(), 0);

        // Receive the response from the server
        int bytes_read = read(sock, buffer, BUFFER_SIZE);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            string response(buffer);
            cout << "Registration response: " << response << endl;
        }

    }
    catch (const exception& ex) {
        cerr << "Error in register(): " << ex.what() << endl;
        exit(-1);
    }

    
}

void Client::login() {

    try {
        string nickname, password;
        cout << "Enter nickname: ";
        getline(cin, nickname);
        password = getPassword();

        // Send login credentials to the server
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Insert the nickname and password into the payload
        // 1 Byte for the nickname length, nickname, 1 Byte for the password length, password
        payload.push_back(nickname.length());
        payload.insert(payload.end(), nickname.begin(), nickname.end());
        payload.push_back(password.length());
        payload.insert(payload.end(), password.begin(), password.end());

        // Construct the packet
        GeneralPacket loginPacket(nonce, T_LOGIN, payload);
        // Send securely to the server
        loginPacket.send(sock, sessionKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, sessionKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            isLoggedIn = true;
            loggedInNickname = nickname;
            cout << "Login successful." << endl;

            // Here there's the need to start another instance of
            // the DH key exchange to generate a new post-login session key
            // because the requirements state that "Upon successful login, 
            // a secure session is established and maintained until the 
            // user logs out."
            DHWrapper dhWrapper(1024);
            postLoginSessionKey = dhWrapper.clientKeyExchange(sock, sessionKey, false, 16);

            postLoginMenu();
            return;
        }
        else if(responsePacket.getType() == T_KO) {
            cout << "Login failed." << endl;
            return;
        }
        else {
            cout << "Not expected response type." << endl;
            exit(-1);
        }

    }
    catch (const exception& ex) {
        cerr << "Error in login(): " << ex.what() << endl;
        exit(-1);
    }
    
}

void Client::logout() {
    isLoggedIn = false;
    postLoginSessionKey.clear();
    loggedInNickname.clear();
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
                listMessages();
                break;
            }
            case 2: {
                getMessage();
                break;
            }
            case 3: {
                addMessage();
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

void Client::listMessages() {
    int n;
    cout << "Enter number of messages to list: ";
    cin >> n;
    cin.ignore();

    string listCommand = "LIST " + to_string(n);
    send(sock, listCommand.c_str(), listCommand.length(), 0);

    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "Messages:\n" << buffer << endl;
    }
}

void Client::getMessage() {
    int mid;
    cout << "Enter message ID to get: ";
    cin >> mid;
    cin.ignore();
    
    string getCommand = "GET " + to_string(mid);
    send(sock, getCommand.c_str(), getCommand.length(), 0);

    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "Message:\n" << buffer << endl;
    }
}

void Client::addMessage() {
    string title, body;
    cout << "Enter title: ";
    getline(cin, title);
    cout << "Enter body: ";
    getline(cin, body);

    // Ask the Server the possibility to add a message
    // In this way it will send back a its nonce to be
    // used in next packets
    vector<unsigned char> nonce = generateRandomBytes(16);
    vector<unsigned char> payload;

    // Construct the packet
    GeneralPacket addMessagePacket(nonce, T_ADD, payload);
    // Send securely to the server
    addMessagePacket.send(sock, postLoginSessionKey);

    // Receive the response from the server
    GeneralPacket responsePacket = GeneralPacket::receive(sock, postLoginSessionKey);

    // First 16 bytes of the aad are the client nonce
    // The next 16 bytes are the server nonce
    vector<unsigned char> receivedClientNonce(responsePacket.getAAD().begin(), responsePacket.getAAD().begin() + 16);
    vector<unsigned char> serverNonce(responsePacket.getAAD().begin() + 16, responsePacket.getAAD().end());
    if(receivedClientNonce != nonce) {
        cout << "Nonce mismatch." << endl;
        exit(-1);
    }

    if(responsePacket.getType() == T_OK) {
        // The server nonce is received, now we can send the message to be added

        // AAD is composed by the client nonce and the server nonce
        vector<unsigned char> aad(nonce);
        aad.insert(aad.end(), serverNonce.begin(), serverNonce.end());

        payload.clear();
        // Pyaload is composed by the title, the author and the body
        // 1 Byte for the title length, title, 1 Byte for the author length, author, 1 Byte for the body length, body
        payload.push_back(title.length());
        payload.insert(payload.end(), title.begin(), title.end());
        payload.push_back(loggedInNickname.length());
        payload.insert(payload.end(), loggedInNickname.begin(), loggedInNickname.end());
        payload.push_back(body.length());
        payload.insert(payload.end(), body.begin(), body.end());

        // Construct the packet
        addMessagePacket.setADD(aad);
        addMessagePacket.setPayload(payload);

        // Send securely to the server
        addMessagePacket.send(sock, postLoginSessionKey);

        // Receive the response from the server
        responsePacket = GeneralPacket::receive(sock, postLoginSessionKey);
        cout <<"Received response packet." << endl;
        if(responsePacket.getAAD() != aad) {
            cout << "Nonces mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            cout << "Message added successfully." << endl;
            return;
        }
        else if(responsePacket.getType() == T_KO) {
            cout << "Impossible to add the message." << endl;
            return;
        }
        else {
            cout << "Not expected response type." << endl;
            exit(-1);
        }

    }
    else if(responsePacket.getType() == T_KO) {
        cout << "Impossible to add the message." << endl;
        return;
    }
    else {
        cout << "Not expected response type." << endl;
        exit(-1);
    }

    // string addCommand = "ADD " + title + " " + loggedInNickname + " " + body;
    // send(sock, addCommand.c_str(), addCommand.length(), 0);

    // int bytes_read = read(sock, buffer, BUFFER_SIZE);
    // if (bytes_read > 0) {
    //     buffer[bytes_read] = '\0';
    //     cout << "Server response:\n" << buffer << endl;
    // }
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
