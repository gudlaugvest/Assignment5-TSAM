// ===================== SERVER =====================

/*
 * TODO: Start TCP server on specified port
 * Steps:
 * 1. Create a TCP socket.
 * 2. Bind the socket to the provided port.
 * 3. Listen for incoming connections from clients or other servers.
 */

 /*
 * TODO: Handle client commands (GETMSG, SENDMSG, LISTSERVERS)
 * Steps:
 * 1. Receive commands from the connected client.
 * 2. Process the commands:
 *    - GETMSG: Fetch a message for the client's group and send it.
 *    - SENDMSG: Store or forward the message to another server.
 *    - LISTSERVERS: Provide the list of currently connected servers.
 */

 /*
 * TODO: Handle inter-server communication
 * Steps:
 * 1. Accept connections from other servers.
 * 2. Respond to commands like HELO, SERVERS, KEEPALIVE, etc.
 * 3. Forward messages to the appropriate servers when necessary.
 */

 /*
 * TODO: Implement message storage and forwarding
 * Steps:
 * 1. Store messages that cannot be immediately delivered.
 * 2. Forward stored messages when the appropriate server is reachable.
 */

 /*
 * TODO: Log all server activities
 * Steps:
 * 1. Maintain a log of all incoming and outgoing messages and commands.
 * 2. Include timestamps for each log entry.
 */


// ===================== SHARED FUNCTIONALITIES =====================

/*
 * TODO: Define message format and parsing logic
 * Steps:
 * 1. Use SOH (0x01) for start of message and EOT (0x04) for end.
 * 2. Implement bytestuffing for escape sequences within messages.
 * 3. Create helper functions to encode and decode messages.
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h> // read(), write(), close()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <signal.h>
#include <poll.h>
#include <fstream>
#include <netdb.h> // For getaddrinfo

using namespace std;

#define BACKLOG 5 // Maximum number of pending connections
#define MAX_SERVERS 8 // Maximum number of connected servers
#define POLL_TIMEOUT -1 // Timeout for poll() in milliseconds
#define SOH 0x01 // ASCII value of SOH (Start of Header)
#define EOT 0x04 // ASCII value of EOT (End of Transmission)
#define MAX_MSG_LEN 5000 // maximum message length

// Group ID
string GROUP_ID = "A5_18"; 

// Struct to hold the server information
struct ServerInfo {
    string groupID;
    string name;
    string ip;
    int port;
};

// Store the connected servers
vector<ServerInfo> connectedServers;
vector<pollfd> fds;  // Declare fds globally

// Function to get the current timestamp
string getTimestamp() {
    time_t now = time(nullptr);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buffer);
}

// Utility function to log messages to a file with a timestamp
void logMessage(const string &message) {
    ofstream logFile("server.log", ios::app); // Open log file in append mode
    if (logFile.is_open()) {
        logFile << "[" << getTimestamp() << "] " << message << endl; // Add timestamp to the log
        logFile.close(); // Close the log file
    } else {
        cerr << "Unable to open log file." << endl; // Handle file open error
    }
}

// Function to create and set up the server socket
int setupServerSocket(int port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, BACKLOG) < 0) {
        perror("Listen failed");
        close(server_socket);
        return -1;
    }

    cout << "Server listening on port: " << port << endl;
    return server_socket;
}

// Helper function to frame messages
string frameMessage(const string& message) {
    return string(1, SOH) + message + string(1, EOT);
}

// Helper function to unframe messages
string unframeMessage(const string& message) {
    if (message.size() > 1 && message.front() == SOH && message.back() == EOT) {
        return message.substr(1, message.size() - 2); // Remove SOH and EOT
    }
    return ""; // Invalid message
}

// Function to send a framed message to a client/server
void sendMessageToSocket(int socket, const string& message) {
    string framedMessage = frameMessage(message);
    ssize_t bytesSent = send(socket, framedMessage.c_str(), framedMessage.size(), 0);
    if (bytesSent < 0) {
        perror("send failed");
    } else {
        cout << "Sent message: " << framedMessage << endl;
    }
}

// Function to receive a framed message from a client/server
string receiveMessageFromSocket(int socket) {
    char buffer[MAX_MSG_LEN] = {0};
    int bytesRead = recv(socket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        perror("recv failed");
        return "";
    }

    buffer[bytesRead] = '\0'; // Null-terminate the string
    string message(buffer);

    return unframeMessage(message); // Return the unframed message
}

// Function to accept new connections and add them to the pollfd vector
void acceptConnections(int serverSocket, vector<pollfd>& fds) {
    int client_socket = accept(serverSocket, nullptr, nullptr);
    if (client_socket < 0) {
        perror("Accept failed");
        return;
    }

    if (fds.size() < MAX_SERVERS + 1) {
        pollfd client_fd;
        client_fd.fd = client_socket;
        client_fd.events = POLLIN;
        fds.push_back(client_fd);
        cout << "New connection accepted." << endl;
    } else {
        cerr << "Maximum clients reached, connection refused." << endl;
        close(client_socket);
    }
}

// Function to process client commands and respond appropriately
void processClientCommand(int clientSocket, vector<pollfd>& fds) {
    string command = receiveMessageFromSocket(clientSocket);
    if (command.empty()) {
        cout << "Client disconnected!" << endl;
        close(clientSocket);

        auto it = find_if(fds.begin(), fds.end(), [&clientSocket](const pollfd& pfd) {
            return pfd.fd == clientSocket;
        });

        if (it != fds.end()) {
            fds.erase(it);
        }
        return;
    }

    // Log the received command
    logMessage("Received command: " + command);

    if (command == "LISTSERVERS") {
        string response = "Connected Servers: " + to_string(fds.size() - 1);
        sendMessageToSocket(clientSocket, response);
        logMessage("Sent LISTSERVERS response.");

    } else if (command == "HELO") {
        string response = "HELO from server: " + GROUP_ID;
        sendMessageToSocket(clientSocket, response);
        logMessage("Sent HELO response.");

    } else if (command == "KEEPALIVE") {
        sendMessageToSocket(clientSocket, "KEEPALIVE ACK");
        logMessage("Sent KEEPALIVE ACK.");
    
    } else if (command.find("SENDMSG") != string::npos) {
        logMessage("Received SENDMSG: " + command);
        sendMessageToSocket(clientSocket, "Message received!");
    
    } else if (command == "GETMSG") {
        string response = "No messages available.";
        sendMessageToSocket(clientSocket, response);
        logMessage("Sent GETMSG response.");
    
    } else {
        string response = "ERROR: Unknown command received.";
        sendMessageToSocket(clientSocket, response);
        logMessage("Sent ERROR response.");
    }
}

// Function to connect to another server
int connectToServer(const string& server_ip, int server_port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        cerr << "Invalid address or address not supported." << endl;
        close(server_socket);
        return -1;
    }

    if (connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(server_socket);
        return -1;
    }

    cout << "Connected to server at " << server_ip << ":" << server_port << endl;
    return server_socket;
}

// Function to send HELO command to another server
void sendHELOToServer(int server_socket) {
    string helo_command = "HELO," + GROUP_ID;
    sendMessageToSocket(server_socket, helo_command);
    logMessage("Sent HELO command to server.");
}

// Function to receive response from another server
string receiveResponseFromServer(int server_socket) {
    string response = receiveMessageFromSocket(server_socket);
    if (!response.empty()) {
        logMessage("Received response from server: " + response);
        cout << "Received response from server: " << response << endl;
    } else {
        cerr << "No response or connection closed by the server." << endl;
    }
    return response;
}

void signalHandler(int signal) {
    cout << "Received signal " << signal << ". Shutting down server..." << endl;
    for (const auto& fd : fds) {
        close(fd.fd);
    }
    exit(0);  // Exit the server
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);

    if (argc != 2) {
        cerr << "Usage: ./tsamgroup18 <port>" << endl;
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int listenSock = setupServerSocket(port);
    if (listenSock < 0) {
        cerr << "Failed to create server. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    // Polling set up
    pollfd server_fd;
    server_fd.fd = listenSock;
    server_fd.events = POLLIN;
    fds.push_back(server_fd);

    cout << "Server is running, waiting for connections..." << endl;

    while (true) {
        int poll_count = poll(fds.data(), fds.size(), POLL_TIMEOUT);
        if (poll_count < 0) {
            perror("Poll failed");
            break;
        }

        if (fds[0].revents & POLLIN) {
            acceptConnections(listenSock, fds);
        }

        for (size_t i = 1; i < fds.size(); i++) {
            if (fds[i].revents & POLLIN) {
                processClientCommand(fds[i].fd, fds);
            }
        }
    }

    return 0;
}
