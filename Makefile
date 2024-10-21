# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -std=c++11

# Define the target executable names
SERVER_TARGET = tsamgroup18
CLIENT_TARGET = client

# Define source files
SERVER_SRC = server.cpp
CLIENT_SRC = client.cpp

# Default rule to build both the server and the client
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Rule to build the server executable
$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $(SERVER_TARGET) $(SERVER_SRC)

# Rule to build the client executable
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRC)

# Clean rule to remove compiled files
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

# Phony targets
.PHONY: all clean
