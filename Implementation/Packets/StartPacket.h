#ifndef START_PACKET_H
#define START_PACKET_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstring>  // For memcpy
#include <sys/socket.h>  // For send/recv


using namespace std;

class StartPacket {
public:
    // Constructor
    StartPacket(const vector<unsigned char>& aad);

    // Serialize the packet into a single vector
    vector<unsigned char> serialize() const;

    // Send securely the packet over a socket
    void send(int socket, vector<unsigned char> key);

    // Static method to receive securely a packet from a socket
    static StartPacket receive(int socket, vector<unsigned char> key);

    // Getters
    const vector<unsigned char>& getAAD() const;

    // Setters
    void setADD(const vector<unsigned char>& aad);

private:
    // Packet Structure:
    // iv (12 Bytes) | aad (670 Bytes) | tag (16 Bytes)
    //
    vector<unsigned char> iv;           // 12 Bytes
    vector<unsigned char> aad;          // 670 Bytes
    vector<unsigned char> tag;          // 16 Bytes

};


#endif // START_PACKET_H
