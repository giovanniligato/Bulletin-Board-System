#include "BulletinBoard.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

BulletinBoard::BulletinBoard(const string& basePath) : basePath(basePath), nextId(0) {
    if (!filesystem::exists(basePath)) {
        filesystem::create_directories(basePath);  // Create the directory if it doesn't exist
    }

    // Initialize the next identifier by checking the highest existing message ID
    vector<Message> messages = loadMessages();
    for (const auto& msg : messages) {
        nextId = max(nextId, msg.identifier + 1);
    }
}

vector<BulletinBoard::Message> BulletinBoard::loadMessages() {
    vector<Message> messages;
    
    for (const auto& entry : filesystem::directory_iterator(basePath)) {
        if (entry.is_regular_file()) {
            string filename = entry.path().filename().string();
            if (filename.find("message_") == 0) {  // Check if it's a message file
                ifstream file(entry.path());
                if (file.is_open()) {
                    Message msg;
                    string line;

                    // Reading the message fields
                    getline(file, line); msg.identifier = stoi(line);
                    getline(file, msg.title);
                    getline(file, msg.author);
                    getline(file, msg.body);

                    messages.push_back(msg);
                    file.close();
                }
            }
        }
    }

    return messages;
}

void BulletinBoard::saveMessage(const Message& msg) {
    ofstream file(basePath + "/message_" + to_string(msg.identifier) + ".txt");
    if (file.is_open()) {
        file << msg.identifier << '\n';
        file << msg.title << '\n';
        file << msg.author << '\n';
        file << msg.body << '\n';
        file.close();
    } else {
        throw runtime_error("Failed to open file for saving message.");
    }
}


void BulletinBoard::add(const string& title, const string& author, const string& body) {
    lock_guard<mutex> lock(boardMutex);

    int id = nextId++;
    Message newMessage{id, title, author, body};
    saveMessage(newMessage);
}

BulletinBoard::Message BulletinBoard::get(int mid) {
    lock_guard<mutex> lock(boardMutex);

    string filePath = basePath + "/message_" + to_string(mid) + ".txt";
    if (filesystem::exists(filePath)) {
        ifstream file(filePath);
        if (file.is_open()) {
            Message msg;
            string line;

            // Read the message fields
            getline(file, line); msg.identifier = stoi(line);
            getline(file, msg.title);
            getline(file, msg.author);
            getline(file, msg.body);

            file.close();
            return msg;
        } else {
            throw runtime_error("Failed to open file for reading message.");
        }
    } else {
        throw runtime_error("Message not found.");
    }
}

vector<BulletinBoard::Message> BulletinBoard::list(int n) {
    lock_guard<mutex> lock(boardMutex);

    vector<Message> allMessages = loadMessages();
    vector<Message> result;

    // Get the latest n messages
    int count = 0;
    for (auto it = allMessages.rbegin(); it != allMessages.rend() && count < n; ++it, ++count) {
        result.push_back(*it);
    }

    return result;
}
