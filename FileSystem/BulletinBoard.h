#ifndef BULLETINBOARD_H
#define BULLETINBOARD_H

#include <string>
#include <vector>
#include <mutex>
#include <filesystem>

using namespace std;

class BulletinBoard {
public:
    struct Message {
        int identifier;
        string title;
        string author;
        string body;
    };

    BulletinBoard(const string& basePath);

    // List the latest n messages
    vector<Message> list(int n);

    // Get a specific message by its identifier
    Message get(int mid);

    // Add a new message to the bulletin board
    void add(const string& title, const string& author, const string& body);

private:
    const string basePath;
    int nextId;
    mutex boardMutex;

    // Helper to load messages from the file system
    vector<Message> loadMessages();

    // Helper to save a message to the file system
    void saveMessage(const Message& msg);

};

#endif // BULLETINBOARD_H
