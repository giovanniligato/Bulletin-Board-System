#include "User.h"


const string User::accountsPath = "Server/Storage/Accounts";
const string User::challengesPath = "Client/Storage/Emails";

User::User(const string& email, const string& nickname, const string& password)
    : email(email), nickname(nickname), password(password) {
    // Generate a random 16-bytes salt
    salt = generateRandomBytes(16);
}

User::User(const string& nickname, const string& password)
    : nickname(nickname), password(password) {
}

bool User::checkExistence() const {
    return filesystem::exists(filesystem::path(accountsPath) / nickname);
}

void User::saveUser() const {
    filesystem::path userPath = filesystem::path(accountsPath) / nickname;
    
    // Create the directory if it does not exist
    if (!filesystem::exists(userPath)) {
        filesystem::create_directory(userPath);
    }

    // Save email, nickname, and salt
    ofstream infoFile(userPath / (nickname + ".txt"), ios::binary);
    if (infoFile.is_open()) {
        infoFile << email << '\n';
        infoFile << nickname << '\n';
        infoFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        infoFile.close();
    } else {
        throw runtime_error("Failed to open file for writing user info.");
    }

    // Compute the salted hashed password
    vector<unsigned char> salted_password(password.begin(), password.end());
    salted_password.insert(salted_password.end(), salt.begin(), salt.end());

    vector<unsigned char> hashed_salted_password = Hash::computeSHA256(salted_password);

    ofstream passwordFile(userPath / "password.txt", ios::binary);
    if (passwordFile.is_open()) {
        passwordFile.write(reinterpret_cast<const char*>(hashed_salted_password.data()), hashed_salted_password.size());
        passwordFile.close();
    } else {
        throw runtime_error("Failed to open file for writing password.");
    }
}

bool User::checkPassword() const {
    filesystem::path userPath = filesystem::path(accountsPath) / nickname;

    // Read the stored salt from the user info file
    ifstream infoFile(userPath / (nickname + ".txt"), ios::binary);
    if (!infoFile.is_open()) {
        throw runtime_error("Failed to open user info file.");
    }

    string storedEmail, storedNickname;
    getline(infoFile, storedEmail); // Read the email (not used in this method)
    getline(infoFile, storedNickname); // Read the nickname (not used in this method)

    vector<unsigned char> storedSalt(16);
    infoFile.read(reinterpret_cast<char*>(storedSalt.data()), storedSalt.size());
    infoFile.close();

    // Read the stored hashed salted password
    ifstream passwordFile(userPath / "password.txt", ios::binary);
    if (!passwordFile.is_open()) {
        throw runtime_error("Failed to open password file.");
    }

    vector<unsigned char> storedHashedSaltedPassword((istreambuf_iterator<char>(passwordFile)), istreambuf_iterator<char>());
    passwordFile.close();

    // Concatenate the current password and the stored salt
    vector<unsigned char> salted_input_password(password.begin(), password.end());
    salted_input_password.insert(salted_input_password.end(), storedSalt.begin(), storedSalt.end());

    // Compute the SHA-256 hash of the current password with the stored salt
    vector<unsigned char> hashedSaltedInputPassword = Hash::computeSHA256(salted_input_password);

    // Compare the hashed salted input password with the stored hashed salted password
    return hashedSaltedInputPassword == storedHashedSaltedPassword;
}

vector<unsigned char> User::sendChallenge() const {

    // Generate a random 4-bytes challenge
    vector<unsigned char> challenge = generateRandomBytes(4);
    uint32_t challengeValue = (static_cast<uint32_t>(challenge[0]) << 24) |  // Most significant byte
                              (static_cast<uint32_t>(challenge[1]) << 16) |
                              (static_cast<uint32_t>(challenge[2]) << 8)  |
                               static_cast<uint32_t>(challenge[3]);          // Least significant byte

    // Save the challengeValue to a file inside the 
    // client's storage simulating an email being sent
    ofstream challengeFile(filesystem::path(challengesPath) / (email + ".txt"), ios::binary);
    if (challengeFile.is_open()) {
        challengeFile << challengeValue;
        challengeFile.close();
    } else {
        throw runtime_error("Failed to open file for writing challenge.");
    }
    
    return challenge;
}

void User::deleteChallenge() const {
    filesystem::remove(filesystem::path(challengesPath) / (email + ".txt"));
}