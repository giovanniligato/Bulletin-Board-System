#ifndef USER_H
#define USER_H

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <stdexcept>

#include "../Utility/Randomness.h"
#include "../Utility/Hash.h"

using namespace std;

class User {
public:
    User(const string& email, const string& nickname, const string& password);
    User(const string& nickname, const string& password);

    bool checkExistence() const;
    
    void saveUser() const;
    
    bool checkPassword() const;

    vector<unsigned char> sendChallenge() const;
    void deleteChallenge() const;

private:
    string email;
    string nickname;
    string password;
    vector<unsigned char> salt;

    static const string accountsPath;
    static const string challengesPath;
};

#endif // USER_H
