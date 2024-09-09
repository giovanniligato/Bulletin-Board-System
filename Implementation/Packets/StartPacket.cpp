#include "StartPacket.h"

#include <stdexcept>
#include <arpa/inet.h>

#include "../Utility/Cryptography/AESGCMWrapper.h"


// Constructor
StartPacket::StartPacket(const vector<unsigned char>& aad)
    : aad(aad) {
    
    if(aad.size() != 670) {
        throw invalid_argument("AAD must be 670 bytes long");
    }
}

// Serialize the packet into a single vector
vector<unsigned char> StartPacket::serialize() const {
    vector<unsigned char> packet;
    
    // Insert IV (12 bytes)
    packet.insert(packet.end(), iv.begin(), iv.end());

    // Insert aad (670 bytes)
    packet.insert(packet.end(), aad.begin(), aad.end());

    // Insert tag (16 bytes)
    packet.insert(packet.end(), tag.begin(), tag.end());

    return packet;
}

// Send securely the packet over a socket
void StartPacket::send(int socket, vector<unsigned char> key) {

    vector<unsigned char> plaintext;
    vector<unsigned char> ciphertext;

    // Authenticated encryption using AES-GCM
    AESGCMWrapper::encrypt(key, plaintext, ciphertext, iv, tag, aad);

    vector<unsigned char> packet = serialize();

    size_t total_bytes = 0;
    size_t packet_size = packet.size();

    // Send the entire packet in chunks
    while (total_bytes < packet_size) {
        ssize_t bytes_sent = ::send(socket, packet.data() + total_bytes, packet_size - total_bytes, 0);
        if (bytes_sent < 0) {
            throw runtime_error("Error sending packet");
        }
        total_bytes += bytes_sent;
    }

}

// Static method to receive securely a packet from a socket
StartPacket StartPacket::receive(int socket, vector<unsigned char> key) {
    vector<unsigned char> packet(698);  // 12 + 670 + 16 bytes

    size_t total_bytes = 0;
    size_t packet_size = packet.size();

    // Receive the entire packet in chunks
    while (total_bytes < packet_size) {
        ssize_t bytes_received = recv(socket, packet.data() + total_bytes, packet_size - total_bytes, 0);
        if (bytes_received < 0) {
            throw runtime_error("Error receiving packet");
        }
        total_bytes += bytes_received;
    }

    // Extract IV (12 bytes)
    vector<unsigned char> iv(packet.begin(), packet.begin() + 12);

    // Extract aad (670 bytes)
    vector<unsigned char> aad(packet.begin() + 12, packet.begin() + 682);

    // Extract tag (16 bytes)
    vector<unsigned char> tag(packet.begin() + 682, packet.end());

    vector<unsigned char> ciphertext;
    vector<unsigned char> plaintext = AESGCMWrapper::decrypt(key, ciphertext, iv, tag, aad);

    return StartPacket(aad);
}


// Getters
const vector<unsigned char>& StartPacket::getAAD() const {
    return aad;
}

// Setters
void StartPacket::setADD(const vector<unsigned char>& aad) {
    if(aad.size() != 670) {
        throw invalid_argument("AAD must be 670 bytes long");
    }
    this->aad = aad;
}
