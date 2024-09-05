#ifndef GENERAL_PACKET_H
#define GENERAL_PACKET_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstring>  // For memcpy
#include <sys/socket.h>  // For send/recv



using namespace std;

class GeneralPacket {
public:
    // Constructor
    GeneralPacket(const vector<unsigned char>& nonce,
                  uint8_t type,
                  const vector<unsigned char>& payload);

    // Serialize the packet into a single vector
    vector<unsigned char> serialize() const;

    // Send securely the packet over a socket
    void send(int socket, vector<unsigned char> key);

    // Static method to receive securely a packet from a socket
    static GeneralPacket receive(int socket, vector<unsigned char> key);

    // Getters
    const vector<unsigned char>& getNonce() const;
    uint8_t getType() const;
    const vector<unsigned char>& getPayload() const;

    // Setters
    void setNonce(const vector<unsigned char>& nonce);
    void setType(uint8_t type);
    void setPayload(const vector<unsigned char>& payload);
    

private:
    uint8_t type;                    
    vector<unsigned char> payload;   

    // Packet Structure:
    // iv (12 Bytes) | nonce (16 Bytes) | ciphertext_size (4 Bytes) | ciphertext (ciphertext_size Bytes) | tag (16 Bytes)
    //
    vector<unsigned char> iv;           // 12 Bytes
    vector<unsigned char> nonce;        // 16 Bytes
    uint32_t ciphertext_size;           // 4 Bytes
    vector<unsigned char> ciphertext;   // ciphertext_size Bytes
    vector<unsigned char> tag;          // 16 Bytes

};


// Possible values for type:
#define T_REGISTRATION 1
#define T_LOGIN 2
#define T_OK 3
#define T_KO 4



#endif // GENERAL_PACKET_H
