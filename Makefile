# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -std=c++11

# Linker flags
LDFLAGS = -lssl -lcrypto -lpthread

# Directories
SERVER_DIR = Server
CLIENT_DIR = Client
UTILITY_CRYPTOGRAPHY_DIR = Utility/Cryptography

# Source files
SERVER_SRC = $(SERVER_DIR)/server.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/RSAWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/DHWrapper.cpp
CLIENT_SRC = $(CLIENT_DIR)/client.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/RSAWrapper.cpp $(UTILITY_CRYPTOGRAPHY_DIR)/DHWrapper.cpp

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
