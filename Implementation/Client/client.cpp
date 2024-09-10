#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <termios.h>

#include "../Utility/Randomness.h"
#include "../Utility/RSAWrapper.h"
#include "../Utility/AESGCMWrapper.h"
#include "../Utility/DHWrapper.h"
#include "../Utility/Hash.h"
#include "../Packets/GeneralPacket.h"

using namespace std;

#define DEFAULT_PORT 3030
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

    bool isLoggedIn = false;
    string loggedInNickname;
    
    // Session key used for the secure session
    vector<unsigned char> sessionKey;

    void connectToServer();
    vector<unsigned char> secureConnection();
    void closeConnection();

    void preLoginMenu();

    void registerUser();
    string getPassword();
    void login();

    void postLoginMenu();

    void listMessages();
    void getMessage();
    void addMessage();
    void logout();
    
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

}

vector<unsigned char> Client::secureConnection() {

    vector<unsigned char> key;
    
    try {

        // Diffie-Hellman key exchange
        DHWrapper dhWrapper(1024);
        
        // As we are using AES128-GCM for symmetric encryption, we need a 128-bit key (16 bytes)
        key = dhWrapper.clientKeyExchange(sock, 16);
    
    }
    catch (const exception& ex) {
        cerr << "Error in secureConnection(): " << ex.what() << endl;
        exit(-1);
    }

    return key;
}


void Client::closeConnection() {
    close(sock);
    cout << "Connection closed." << endl;
}

void Client::preLoginMenu() {

    while (!isLoggedIn) {
        cout << "\n--- Login Menu ---" << endl;
        cout << "1. Register" << endl;
        cout << "2. Login" << endl;
        cout << "3. Exit" << endl;
        cout << "Choose an option: ";
        
        string choice;
        getline(cin, choice);

        int choiceInt;
        try{
            choiceInt = stoi(choice);
        }
        catch (const exception& ex) {
            choiceInt = -1;
        }

        cout << endl;
        switch (choiceInt) {
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

    // If password is longer than 255 characters, truncate it
    if (password.length() > 255) {
        password = password.substr(0, 255);
    }

    // Restore old terminal attributes
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    cout << endl;

    return password;
}

void Client::registerUser() {

    try {
        
        // Starting the "secure connection" for the registration
        vector<unsigned char> temporaryKey = secureConnection();

        string email, nickname, password;
        cout << "Enter email: ";
        getline(cin, email);

        // If email is longer than 255 characters, truncate it
        if (email.length() > 255) {
            email = email.substr(0, 255);
        }

        cout << "Enter nickname: ";
        getline(cin, nickname);
        
        // If nickname is longer than 255 characters, truncate it
        if (nickname.length() > 255) {
            nickname = nickname.substr(0, 255);
        }
        
        password = getPassword();

        // Send registration credentials to the server
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Insert the email, nickname, and password into the payload
        // 1 Byte for the email length, email, 
        // 1 Byte for the nickname length, nickname, 
        // 1 Byte for the password length, password
        payload.push_back(email.length());
        payload.insert(payload.end(), email.begin(), email.end());
        payload.push_back(nickname.length());
        payload.insert(payload.end(), nickname.begin(), nickname.end());
        payload.push_back(password.length());
        payload.insert(payload.end(), password.begin(), password.end());

        // Construct the packet
        GeneralPacket registrationPacket(nonce, T_REGISTRATION, payload);
        // Send securely to the server
        registrationPacket.send(sock, temporaryKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, temporaryKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            cout << "Challenge sent to your email (Client/Storage/Emails/" << email << ".txt)." << endl;
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
            registrationPacket.send(sock, temporaryKey);

            // Receive the response from the server
            responsePacket = GeneralPacket::receive(sock, temporaryKey);

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

    }
    catch (const exception& ex) {
        cerr << "Error in registerUser(): " << ex.what() << endl;
        exit(-1);
    }

}

void Client::login() {

    try {

        // Starting the "secure connection" for the login
        vector<unsigned char> temporaryKey = secureConnection();

        string nickname, password;
        cout << "Enter nickname: ";
        getline(cin, nickname);

        // If nickname is longer than 255 characters, truncate it
        if (nickname.length() > 255) {
            nickname = nickname.substr(0, 255);
        }

        password = getPassword();

        // Send login credentials to the server
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Insert the nickname and password into the payload
        // 1 Byte for the nickname length, nickname, 
        // 1 Byte for the password length, password
        payload.push_back(nickname.length());
        payload.insert(payload.end(), nickname.begin(), nickname.end());
        payload.push_back(password.length());
        payload.insert(payload.end(), password.begin(), password.end());

        // Construct the packet
        GeneralPacket loginPacket(nonce, T_LOGIN, payload);
        // Send securely to the server
        loginPacket.send(sock, temporaryKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, temporaryKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            isLoggedIn = true;
            loggedInNickname = nickname;
            cout << "Login successful." << endl;

            // Here we can establish a secure session
            // with the server, saving the temporary key
            // intp the session key, in order to be used
            // for the following operations 
            sessionKey = temporaryKey;

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

void Client::postLoginMenu() {
    
    while (isLoggedIn) {
        cout << "\n---- BBS Menu ----" << endl;
        cout << "1. List Messages" << endl;
        cout << "2. Get Message" << endl;
        cout << "3. Add Message" << endl;
        cout << "4. Logout" << endl;
        cout << "Choose an option: ";
        
        string choice;
        getline(cin, choice);

        int choiceInt;
        try{
            choiceInt = stoi(choice);
        }
        catch (const exception& ex) {
            choiceInt = -1;
        }

        cout << endl;
        switch (choiceInt) {
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

    try{

        uint32_t n;
        cout << "Enter number of latest messages to list (if available): ";
        cin >> n;
        cin.ignore();

        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;
        
        // Adding n to the payload
        payload.push_back((n >> 24) & 0xFF);
        payload.push_back((n >> 16) & 0xFF);
        payload.push_back((n >> 8) & 0xFF);
        payload.push_back(n & 0xFF);

        // Construct the packet
        GeneralPacket listMessagesPacket(nonce, T_LIST, payload);

        // Send securely to the server
        listMessagesPacket.send(sock, sessionKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, sessionKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            // Inside the payload there are:
            // 4 Bytes indicating the actual number of messages
            // (because the server may not have n messages to list)
            // Then, for each message, there are:
            // 4 Bytes for the message ID
            // 2 Bytes for the title length, title, 
            // 1 Byte for the author length, author
            // 2 Bytes for the body length, body
            vector<unsigned char> listMessagesPayload = responsePacket.getPayload();

            uint32_t actualNumberOfMessages = (listMessagesPayload[0] << 24) | (listMessagesPayload[1] << 16) | (listMessagesPayload[2] << 8) | listMessagesPayload[3];
            // Remove the actual number of messages from the payload
            listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + 4);

            if(actualNumberOfMessages == 0) {
                cout << "No messages to list." << endl;
                return;
            }

            cout << actualNumberOfMessages << " messages found." << endl << endl;
            for (uint32_t i = 0; i < actualNumberOfMessages; i++) {
                uint32_t mid = (listMessagesPayload[0] << 24) | (listMessagesPayload[1] << 16) | (listMessagesPayload[2] << 8) | listMessagesPayload[3];
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + 4);
                uint16_t titleLength = (listMessagesPayload[0] << 8) | listMessagesPayload[1];
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + 2);
                string title(listMessagesPayload.begin(), listMessagesPayload.begin() + titleLength);
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + titleLength);
                uint8_t authorLength = listMessagesPayload[0];
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + 1);
                string author(listMessagesPayload.begin(), listMessagesPayload.begin() + authorLength);
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + authorLength);
                uint16_t bodyLength = (listMessagesPayload[0] << 8) | listMessagesPayload[1];
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + 2);
                string body(listMessagesPayload.begin(), listMessagesPayload.begin() + bodyLength);
                listMessagesPayload.erase(listMessagesPayload.begin(), listMessagesPayload.begin() + bodyLength);

                cout << "Message ID: " << mid << endl;
                cout << "Title: " << title << endl;
                cout << "Author: " << author << endl;
                cout << "Body: " << body << endl;
                cout << endl;
            }

            cout << "End of messages." << endl;

            return;
        
        }
        else if(responsePacket.getType() == T_KO) {
            cout << "Impossible to list the messages." << endl;
            return;
        }
        else {
            cout << "Not expected response type." << endl;
            exit(-1);
        }

    }
    catch (const exception& ex) {
        cerr << "Error in listMessages(): " << ex.what() << endl;
        exit(-1);
    }

}

void Client::getMessage() {

    try{

        uint32_t mid;
        cout << "Enter message ID to get: ";
        cin >> mid;
        cin.ignore();
        
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Adding mid to the payload
        payload.push_back((mid >> 24) & 0xFF);
        payload.push_back((mid >> 16) & 0xFF);
        payload.push_back((mid >> 8) & 0xFF);
        payload.push_back(mid & 0xFF);

        // Construct the packet
        GeneralPacket getMessagePacket(nonce, T_GET, payload);

        // Send securely to the server
        getMessagePacket.send(sock, sessionKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, sessionKey);
        if(responsePacket.getAAD() != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        cout << endl;
        if(responsePacket.getType() == T_OK) {
            // Inside the payload there are:
            // 4 Bytes for the message ID
            // 2 Bytes for the title length, title, 
            // 1 Byte for the author length, author
            // 2 Bytes for the body length, body
            vector<unsigned char> getMessagePayload = responsePacket.getPayload();
            uint32_t mid = (getMessagePayload[0] << 24) | (getMessagePayload[1] << 16) | (getMessagePayload[2] << 8) | getMessagePayload[3];
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + 4);
            uint16_t titleLength = (getMessagePayload[0] << 8) | getMessagePayload[1];
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + 2);
            string title(getMessagePayload.begin(), getMessagePayload.begin() + titleLength);
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + titleLength);
            uint8_t authorLength = getMessagePayload[0];
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + 1);
            string author(getMessagePayload.begin(), getMessagePayload.begin() + authorLength);
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + authorLength);
            uint16_t bodyLength = (getMessagePayload[0] << 8) | getMessagePayload[1];
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + 2);
            string body(getMessagePayload.begin(), getMessagePayload.begin() + bodyLength);
            getMessagePayload.erase(getMessagePayload.begin(), getMessagePayload.begin() + bodyLength);

            cout << "Message ID: " << mid << endl;
            cout << "Title: " << title << endl;
            cout << "Author: " << author << endl;
            cout << "Body: " << body << endl;

            return;
        }
        else if(responsePacket.getType() == T_KO) {
            cout << "Impossible to get the message." << endl;
            return;
        }
        else {
            cout << "Not expected response type." << endl;
            exit(-1);
        }

    }
    catch (const exception& ex) {
        cerr << "Error in getMessage(): " << ex.what() << endl;
        exit(-1);
    }
    
}

void Client::addMessage() {

    try{

        string title, body;
        cout << "Enter title: ";
        getline(cin, title);
        
        // If title is longer than 65535 characters, truncate it
        if (title.length() > 65535) {
            title = title.substr(0, 65535);
        }

        cout << "Enter body: ";
        getline(cin, body);

        // If body is longer than 65535 characters, truncate it
        if (body.length() > 65535) {
            body = body.substr(0, 65535);
        }

        // Ask the Server the possibility to add a 
        // message. In this way it will send back 
        // its nonce to be used in next packets
        vector<unsigned char> nonce = generateRandomBytes(16);
        vector<unsigned char> payload;

        // Construct the packet
        GeneralPacket addMessagePacket(nonce, T_ADD, payload);
        // Send securely to the server
        addMessagePacket.send(sock, sessionKey);

        // Receive the response from the server
        GeneralPacket responsePacket = GeneralPacket::receive(sock, sessionKey);

        // First 16 bytes of the aad are the client nonce
        // The next 16 bytes are the server nonce
        vector<unsigned char> receivedClientNonce(responsePacket.getAAD().begin(), responsePacket.getAAD().begin() + 16);
        vector<unsigned char> serverNonce(responsePacket.getAAD().begin() + 16, responsePacket.getAAD().end());
        if(receivedClientNonce != nonce) {
            cout << "Nonce mismatch." << endl;
            exit(-1);
        }

        if(responsePacket.getType() == T_OK) {
            // The server nonce has been received, 
            // now we can send the message to be added

            // AAD is composed by the client nonce and the server nonce
            vector<unsigned char> aad(nonce);
            aad.insert(aad.end(), serverNonce.begin(), serverNonce.end());

            payload.clear();
            // Pyaload is composed by the title, the author and the body
            // 2 Bytes for the title length, title, 
            // 1 Byte for the author length, author, 
            // 2 Bytes for the body length, body
            payload.push_back((title.length() >> 8) & 0xFF);
            payload.push_back(title.length() & 0xFF);
            payload.insert(payload.end(), title.begin(), title.end());
            payload.push_back(loggedInNickname.length());
            payload.insert(payload.end(), loggedInNickname.begin(), loggedInNickname.end());
            payload.push_back((body.length() >> 8) & 0xFF);
            payload.push_back(body.length() & 0xFF);
            payload.insert(payload.end(), body.begin(), body.end());
            
            // Construct the packet
            addMessagePacket.setADD(aad);
            addMessagePacket.setPayload(payload);

            // Send securely to the server
            addMessagePacket.send(sock, sessionKey);

            // Receive the response from the server
            responsePacket = GeneralPacket::receive(sock, sessionKey);
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

    }
    catch (const exception& ex) {
        cerr << "Error in addMessage(): " << ex.what() << endl;
        exit(-1);
    }

}

void Client::logout() {

    try{
        vector<unsigned char> nonce;
        vector<unsigned char> payload;

        // Construct the packet
        GeneralPacket logoutPacket(nonce, T_LOGOUT, payload);

        // Send securely to the server
        logoutPacket.send(sock, sessionKey);

        isLoggedIn = false;
        sessionKey.clear();
        loggedInNickname.clear();

        cout << "Logged out successfully." << endl;
    }   
    catch (const exception& ex) {
        cerr << "Error in logout(): " << ex.what() << endl;
        exit(-1);
    }

}

void Client::run() {

    // Establish basic connection with the server
    connectToServer();

    // Show the pre-login menu
    preLoginMenu();
}

// Main function
int main(int argc, char *argv[]) {

    int PORT = DEFAULT_PORT;

    if (argc > 1) {
        PORT = stoi(argv[1]);
    }

    try {
        Client client(SERVER_ADDRESS, PORT);
        client.run();
    } 
    catch (const exception& ex) {
        cerr << "Error in main(): " << ex.what() << endl;
        return -1;
    }

    return 0;
}
