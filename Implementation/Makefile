# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -std=c++17

# Linker flags
LDFLAGS = -lssl -lcrypto -lpthread

# Directories
SERVER_DIR = Server
CLIENT_DIR = Client
UTILITY_CRYPTOGRAPHY_DIR = Utility
PACKETS_DIR = Packets
FILESYSTEM_DIR = FileSystem

# Source files
SERVER_SRC = $(SERVER_DIR)/server.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/RSAWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/DHWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/AESGCMWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/Randomness.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/Hash.cpp $(PACKETS_DIR)/GeneralPacket.cpp $(PACKETS_DIR)/StartPacket.cpp $(FILESYSTEM_DIR)/User.cpp $(FILESYSTEM_DIR)/BulletinBoard.cpp
CLIENT_SRC = $(CLIENT_DIR)/client.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/RSAWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/DHWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/AESGCMWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/Randomness.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/Hash.cpp $(PACKETS_DIR)/GeneralPacket.cpp $(PACKETS_DIR)/StartPacket.cpp

# Output executables
SERVER_EXE = serverBBS
CLIENT_EXE = clientBBS

# Default target
all: $(SERVER_EXE) $(CLIENT_EXE)

# Compile the server executable
$(SERVER_EXE): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER_EXE) $(LDFLAGS)

# Compile the client executable
$(CLIENT_EXE): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT_EXE) $(LDFLAGS)

# Clean target
clean:
	rm -f $(SERVER_EXE) $(CLIENT_EXE)

# Phony targets (not actual files)
.PHONY: all clean
