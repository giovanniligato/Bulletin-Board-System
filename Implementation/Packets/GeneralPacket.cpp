#include "GeneralPacket.h"

#include <arpa/inet.h>
#include "../Utility/AESGCMWrapper.h"

// Constructor
GeneralPacket::GeneralPacket(const vector<unsigned char>& aad,
                             uint8_t type,
                             const vector<unsigned char>& payload)
    : type(type), payload(payload), aad_size(aad.size()), aad(aad) {
}

// Serialize the packet into a single vector
vector<unsigned char> GeneralPacket::serialize() const {
    vector<unsigned char> packet;
    
    // Insert IV (12 bytes)
    packet.insert(packet.end(), iv.begin(), iv.end());

    // Insert aad_size (4 bytes)
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&aad_size),
                  reinterpret_cast<const unsigned char*>(&aad_size) + sizeof(aad_size));

    // Insert aad (aad_size bytes)
    packet.insert(packet.end(), aad.begin(), aad.end());

    // Insert ciphertext_size (4 bytes)
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&ciphertext_size),
                  reinterpret_cast<const unsigned char*>(&ciphertext_size) + sizeof(ciphertext_size));

    // Insert ciphertext (ciphertext_size bytes)
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());

    // Insert tag (16 bytes)
    packet.insert(packet.end(), tag.begin(), tag.end());

    return packet;
}


// Send securely the packet over a socket
void GeneralPacket::send(int socket, vector<unsigned char> key) {

    // Compose the plaintext: TYPE (1 Byte) || PAYLOAD
    vector<unsigned char> plaintext;
    plaintext.push_back(type);
    plaintext.insert(plaintext.end(), payload.begin(), payload.end());

    // Authenticated encryption using AES-GCM
    AESGCMWrapper::encrypt(key, plaintext, ciphertext, iv, tag, aad);

    ciphertext_size = ciphertext.size();

    vector<unsigned char> packet = serialize();

    size_t total_bytes = 0;
    size_t packet_size = packet.size();

    // Send the entire packet in chunks
    while (total_bytes < packet_size) {
        ssize_t bytes_sent = ::send(socket, packet.data() + total_bytes, packet_size - total_bytes, 0);
        if (bytes_sent < 0) {
            throw runtime_error("Failed to send packet");
        }
        total_bytes += bytes_sent;
    }
}

// Static method to receive securely a packet from a socket
GeneralPacket GeneralPacket::receive(int socket, vector<unsigned char> key) {

    // First receive the fixed header (12 bytes IV + 4 bytes aad_size)
    vector<unsigned char> header(16);  // 16 bytes for fixed-size header
    size_t total_received = 0;

    // Receive the fixed part of the packet (header)
    while (total_received < header.size()) {
        ssize_t bytes_received = ::recv(socket, header.data() + total_received, header.size() - total_received, 0);
        if (bytes_received < 0) {
            throw runtime_error("Failed to receive packet header");
        } else if (bytes_received == 0) {
            throw runtime_error("Connection closed by peer");
        }
        total_received += bytes_received;
    }

    // Deserialize the header to extract the aad_size
    vector<unsigned char> iv(header.begin(), header.begin() + 12);
    uint32_t aad_size;
    memcpy(&aad_size, &header[12], sizeof(aad_size));
    
    // Now receive the variable-length aad based on aad_size
    vector<unsigned char> aad(aad_size);
    total_received = 0;

    while (total_received < aad_size) {
        ssize_t bytes_received = ::recv(socket, aad.data() + total_received, aad_size - total_received, 0);
        if (bytes_received < 0) {
            throw runtime_error("Failed to receive packet aad");
        }
        total_received += bytes_received;
    }

    // Receive again the fixed part of the packet (4 bytes ciphertext_size)
    header.resize(4); // 4 bytes for fixed-size ciphertext_size
    total_received = 0;

    while (total_received < header.size()) {
        ssize_t bytes_received = ::recv(socket, header.data() + total_received, header.size() - total_received, 0);
        if (bytes_received < 0) {
            throw runtime_error("Failed to receive iphertext_size");
        } else if (bytes_received == 0) {
            throw runtime_error("Connection closed by peer");
        }
        total_received += bytes_received;
    }

    // Extract the ciphertext_size
    uint32_t ciphertext_size;
    memcpy(&ciphertext_size, &header[0], sizeof(ciphertext_size));

    // Now receive the variable-length ciphertext based on ciphertext_size
    vector<unsigned char> ciphertext(ciphertext_size);
    total_received = 0;

    while (total_received < ciphertext_size) {
        ssize_t bytes_received = ::recv(socket, ciphertext.data() + total_received, ciphertext_size - total_received, 0);
        if (bytes_received < 0) {
            throw runtime_error("Failed to receive packet ciphertext");
        }
        total_received += bytes_received;
    }

    // Finally, receive the tag (16 bytes)
    vector<unsigned char> tag(16);
    total_received = 0;

    while (total_received < tag.size()) {
        ssize_t bytes_received = ::recv(socket, tag.data() + total_received, tag.size() - total_received, 0);
        if (bytes_received < 0) {
            throw runtime_error("Failed to receive packet tag");
        }
        total_received += bytes_received;
    }

    // Decrypt the ciphertext
    vector<unsigned char> plaintext = AESGCMWrapper::decrypt(key, ciphertext, iv, tag, aad);

    // Extract the type and payload from the plaintext
    uint8_t type = plaintext[0];
    vector<unsigned char> payload(plaintext.begin() + 1, plaintext.end());

    // Return the GeneralPacket
    return GeneralPacket(aad, type, payload);
}

// Getters
const vector<unsigned char>& GeneralPacket::getAAD() const { return aad; }
uint8_t GeneralPacket::getType() const { return type; }
const vector<unsigned char>& GeneralPacket::getPayload() const { return payload; }

// Setters
void GeneralPacket::setADD(const vector<unsigned char>& aad) { 
    this->aad_size = aad.size();
    this->aad = aad; 
}
void GeneralPacket::setType(uint8_t type) { this->type = type; }
void GeneralPacket::setPayload(const vector<unsigned char>& payload) { this->payload = payload; }


