#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <unistd.h> // read(), write(), close()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <signal.h>
#include <poll.h>
#include <fstream>
#include <netdb.h> // For getaddrinfo
#include <sstream> // For stringstream
#include <thread> // For thread operations
#include <chrono> // For sleep in thread
#include <map> // For message storage
#include <mutex> // For thread safety

using namespace std;

#define BACKLOG 5 // Maximum number of pending connections
#define MAX_SERVERS 8 // Maximum number of connected servers
#define POLL_TIMEOUT -1 // Timeout for poll() in milliseconds
#define SOH 0x01 // ASCII value of SOH (Start of Header)
#define EOT 0x04 // ASCII value of EOT (End of Transmission)
#define MAX_MSG_LEN 5000 // maximum message length
#define KEEPALIVE_INTERVAL 60 // Send KEEPALIVE every 30 seconds

// Group ID
string GROUP_ID = "A5_18"; 

// Struct to hold the server information
struct ServerInfo {
    string groupID;
    string name;
    string ip;
    int port;
    bool active;
    int sockfd;
    time_t lastKeepAlive;
};

// Store the connected servers
vector<ServerInfo> connectedServers;
vector<pollfd> fds;  // Declare fds globally
map<string, vector<string>> messageQueues;  // Store messages for each group
mutex serverMutex;  // Mutex for thread safety

// Global variable to store messages for each group
map<string, vector<string>> groupMessages;  // Maps group ID to a list of messages

// Function to get the current timestamp
string getTimestamp() {
    time_t now = time(nullptr);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buffer);
}

// Function to log messages to a file
void logMessage(const string& level, const string& message) {
    ofstream logFile("server.log", ios::app); // Open log file in append mode
    if (logFile.is_open()) {
        logFile << "[" << getTimestamp() << "] [" << level << "] " << message << endl; // Add timestamp and log level to the log
        logFile.close(); // Close the log file
    } else {
        cerr << "Unable to open log file." << endl; // Handle file open error
    }
}


// Function to retrieve the public IPv4 address using an external service
string getPublicIP() {
    string command = "curl -s4 ifconfig.me";
    array<char, 128> buffer;
    string result;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) throw runtime_error("popen() failed!");

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}

// Do we need this function????

// Ping function to check if the other server is reachable
bool pingServer(const string& ip) {
    string pingCmd = "ping -c 1 " + ip;
    int result = system(pingCmd.c_str());
    return result == 0; // Return true if ping is successful
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

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
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

// Function to split a string by a delimiter
vector<string> splitString(const string& str, char delimiter) {
    vector<string> tokens;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    tokens.push_back(str.substr(start)); // Add the last token
    return tokens;
}


// Function to send a framed message to a client/server with retry logic
void sendMessageToSocket(int socket, const string& message, int maxRetries = 3, int retryDelayMs = 500) {
    string framedMessage = frameMessage(message);
    ssize_t bytesSent;
    int attempts = 0;

    while (attempts < maxRetries) {
        bytesSent = send(socket, framedMessage.c_str(), framedMessage.size(), 0);

        if (bytesSent >= 0) {
            cout << "Sent message: " << framedMessage << endl;
            return; // Success, no need to retry
        } else {
            // Handle specific errors
            if (errno == EPIPE) {
                cerr << "Error: Broken pipe. The connection is closed by the peer." << endl;
                close(socket); // Close the socket
                return; // Exit immediately, broken pipe cannot be retried
            } else if (errno == ECONNRESET) {
                cerr << "Error: Connection reset by peer." << endl;
                close(socket); // Close the socket
                return; // Exit immediately, connection reset cannot be retried
            } else if (errno == ENETUNREACH) {
                cerr << "Error: Network unreachable." << endl;
            } else {
                cerr << "Error: send() failed with error: " << strerror(errno) << endl;
            }

            // Retry after a short delay for transient errors
            attempts++;
            cerr << "Retrying send (" << attempts << "/" << maxRetries << ")..." << endl;
            this_thread::sleep_for(chrono::milliseconds(retryDelayMs));
        }
    }

    cerr << "Failed to send message after " << maxRetries << " attempts. Giving up." << endl;
}

// Function to receive a framed message from a client/server
string receiveMessageFromSocket(int socket, int maxRetries = 3, int retryDelayMs = 500) {
    char buffer[MAX_MSG_LEN] = {0};
    int attempts = 0;
    ssize_t bytesRead;

    while (attempts < maxRetries) {
        bytesRead = recv(socket, buffer, sizeof(buffer) - 1, 0); // Reserve space for null-termination

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0'; // Null-terminate the string
            string message(buffer);
            return unframeMessage(message); // Return the unframed message
        } else if (bytesRead == 0) {
            // If recv returns 0, the peer has performed an orderly shutdown
            cout << "Client disconnected gracefully." << endl;
            close(socket); // Close the socket
            return ""; // No data received
        } else {
            // If recv returns an error
            if (errno == ECONNRESET) {
                cerr << "Error: Connection reset by peer." << endl;
                close(socket); // Close the socket
                return ""; // Exit immediately, connection reset cannot be retried
            } else if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK) {
                cerr << "Warning: Transient error during receiving, retrying (" 
                     << attempts + 1 << "/" << maxRetries << ")..." << endl;
            } else {
                cerr << "Error: recv() failed with error: " << strerror(errno) << endl;
                close(socket); // Close socket on non-recoverable error
                return "";
            }

            // If it's a transient error, retry after a short delay
            attempts++;
            this_thread::sleep_for(chrono::milliseconds(retryDelayMs));
        }
    }

    cerr << "Error: Max retries reached, giving up on receiving data." << endl;
    close(socket); // Close the socket as max retries reached
    return ""; // Failed to receive data within max retries
}


// Function to parse KEEPALIVE messages and update the server's lastKeepAlive time
int parseKeepAliveMessage(const string& command, ServerInfo& server) {
    size_t delimiterPos = command.find(',');
    if (delimiterPos != string::npos) {
        // Extract the message count part
        string messageCountStr = command.substr(delimiterPos + 1);
        
        try {
            // Convert string to int and return the message count
            int messageCount = stoi(messageCountStr);
            
            // Update the lastKeepAlive timestamp for this server
            server.lastKeepAlive = time(0);
            
            logMessage("DEBUG", "Parsed KEEPALIVE from " + server.groupID + " with message count " + to_string(messageCount));

            return messageCount;
        } catch (const invalid_argument&) {
            cerr << "Invalid message count in KEEPALIVE command." << endl;
            return 0; // Default or error value
        } catch (const out_of_range&) {
            cerr << "Message count out of range in KEEPALIVE command." << endl;
            return 0; // Default or error value
        }
    }
    return 0; // If no message count found
}

// Function to send KEEPALIVE messages periodically and remove inactive servers
void sendKeepAlive() {
    while (true) {
        this_thread::sleep_for(chrono::seconds(KEEPALIVE_INTERVAL));
        logMessage("INFO", "Sending KEEPALIVE to all connected servers.");

        lock_guard<mutex> lock(serverMutex);  // Ensure thread-safe access to connected servers

        time_t currentTime = time(0);  // Get the current time

        logMessage("DEBUG", "Number of connected servers: " + to_string(connectedServers.size()));

        for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
            ServerInfo& server = *it;  // Access the server info directly

            // Check if the server hasn't sent a KEEPALIVE for more than 120 seconds
            double timeSinceLastKeepAlive = difftime(currentTime, server.lastKeepAlive);
            logMessage("DEBUG", "Time since last KEEPALIVE for server " + server.groupID + ": " + to_string(timeSinceLastKeepAlive));

            if (timeSinceLastKeepAlive > 120) {
                logMessage("WARNING", "Server " + server.groupID + " has been inactive for too long. Closing connection.");
                close(server.sockfd);  // Close the socket

                // Remove the server's pollfd entry from the fds vector
                auto fd_it = find_if(fds.begin(), fds.end(), [&](pollfd const& pfd) {
                    return pfd.fd == server.sockfd;
                });
                if (fd_it != fds.end()) {
                    fds.erase(fd_it);
                }

                it = connectedServers.erase(it);  // Remove the server and update iterator
                continue;  // Move to the next server
            }

            // Only send a KEEPALIVE message if 60 seconds have passed since the last one
            if (difftime(currentTime, server.lastKeepAlive) >= 60) {
                // Count the number of messages waiting for this server
                int numMessages = messageQueues.count(server.groupID) ? messageQueues[server.groupID].size() : 0;

                // Create the KEEPALIVE message
                string keepAliveMsg = frameMessage("KEEPALIVE," + to_string(numMessages));

                logMessage("DEBUG", "Attempting to send KEEPALIVE to server " + server.groupID + " with socket " + to_string(server.sockfd));
                
                // Check if the socket is valid before sending
                if (server.sockfd >= 0) {
                    ssize_t result = send(server.sockfd, keepAliveMsg.c_str(), keepAliveMsg.length(), 0);
                    if (result < 0) {
                        logMessage("ERROR", "send() failed for server " + server.groupID + " with socket " + to_string(server.sockfd) + " errno: " + string(strerror(errno)));
                    } else {
                        // Update the lastKeepAlive time on successful send
                        server.lastKeepAlive = currentTime;
                        logMessage("INFO", "Sent KEEPALIVE to server " + server.groupID + " with " + to_string(numMessages) + " messages.");
                    }
                } else {
                    logMessage("ERROR", "Invalid socket for server " + server.groupID + ". Skipping send.");
                }
            }

            ++it;  // Move to the next server
        }
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
    string heloMessage = "HELO," + GROUP_ID;
    sendMessageToSocket(server_socket, heloMessage);
    logMessage("INFO", "Sent HELO to server at " + server_ip + ":" + to_string(server_port));
    return server_socket;
}

void handleServersResponse(const string& serversList, vector<pollfd>& fds) {
    // Parse the server list starting after "SERVERS,"
    vector<string> servers = splitString(serversList, ';');

    for (const auto& serverInfo : servers) {
        vector<string> fields = splitString(serverInfo, ',');
        if (fields.size() == 3) {
            string groupID = fields[0];
            string ipAddress = fields[1];
            int serverPort = stoi(fields[2]);

            // Check if this server is already connected
            bool alreadyConnected = any_of(connectedServers.begin(), connectedServers.end(), 
                [&](const ServerInfo& server) { return server.ip == ipAddress && server.port == serverPort; });

            if (!alreadyConnected) {
                // Connect to the new server
                int serverSockfd = connectToServer(ipAddress, serverPort);
                if (serverSockfd >= 0) {
                    // Add the server to connectedServers
                    ServerInfo newServer = {groupID, "Server_" + groupID, ipAddress, serverPort, true, serverSockfd, time(0)};
                    connectedServers.push_back(newServer);

                    // Add the new server to fds for polling
                    pollfd newPollFd;
                    newPollFd.fd = serverSockfd;
                    newPollFd.events = POLLIN;
                    fds.push_back(newPollFd);

                    logMessage("INFO", "Connected to new server " + groupID + " at " + ipAddress + ":" + to_string(serverPort));
                } else {
                    logMessage("ERROR", "Failed to connect to server: " + groupID);
                }
            } else {
                logMessage("INFO", "Already connected to server " + groupID + " at " + ipAddress + ":" + to_string(serverPort));
            }
        } else {
            logMessage("ERROR", "Invalid server info format in SERVERS response: " + serverInfo);
        }
    }
}

// Function to retrieve messages for a given group
string retrieveMessagesForGroup(const string& groupID) {
    // Check if the group exists in the map
    auto it = groupMessages.find(groupID);
    if (it != groupMessages.end() && !it->second.empty()) {
        // Construct the response with all messages for the group
        stringstream response;
        response << "Messages for group " << groupID << ": ";
        
        for (const auto& message : it->second) {
            response << message << "; ";  // Append each message with a separator
        }
        return response.str();  // Return the concatenated messages
    }
    return "No messages available for group " + groupID + ".";
}

void processClientCommand(int clientSocket, vector<pollfd>& fds, int port) {
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
    logMessage("INFO", "Received command: " + command);

    // Check for HELO command
    if (command.find("HELO") == 0) {
        string serversList = "SERVERS," + GROUP_ID + "," + getPublicIP() + "," + to_string(port) + ";";
        for (const auto& server : connectedServers) {
            serversList += server.groupID + "," + server.ip + "," + to_string(server.port) + ";";
        }
        sendMessageToSocket(clientSocket, serversList);
        logMessage("INFO", "Sent SERVERS response: " + serversList);

    } else if (command.find("SERVERS") == 0) {
        string serversList = command.substr(8);  // Remove "SERVERS," from the command
        handleServersResponse(serversList, fds);
        logMessage("INFO", "Processed SERVERS command.");

    } else if (command == "LISTSERVERS") {
        string response = "Connected Servers: " + to_string(fds.size() - 1);
        sendMessageToSocket(clientSocket, response);
        logMessage("INFO", "Sent LISTSERVERS response: " + response);

    } else if (command.find("SENDMSG") == 0) {
        // Parse SENDMSG command
        size_t pos1 = command.find(",", 8); // Find first comma after SENDMSG
        size_t pos2 = command.find(",", pos1 + 1); // Find second comma
        if (pos1 != string::npos && pos2 != string::npos) {
            string toGroupID = command.substr(8, pos1 - 8);
            string fromGroupID = command.substr(pos1 + 1, pos2 - pos1 - 1);
            string messageContent = command.substr(pos2 + 1);

            if (messageContent.size() > 5000) {
                string response = "ERROR: Message exceeds maximum length of 5000 bytes.";
                sendMessageToSocket(clientSocket, response);
                logMessage("ERROR", response);
            } else {
                // Store the message in the group's message list
                groupMessages[toGroupID].push_back(messageContent);
                logMessage("INFO", "Message sent from " + fromGroupID + " to " + toGroupID + ": " + messageContent);
                sendMessageToSocket(clientSocket, "Message received!");
            }
        } else {
            string response = "ERROR: SENDMSG command format invalid.";
            sendMessageToSocket(clientSocket, response);
            logMessage("ERROR", response);
        }

    } else if (command.find("GETMSGS") == 0) {
        size_t pos = command.find(","); // Find comma
        if (pos != string::npos) {
            string groupID = command.substr(8, pos - 8);
            // Logic to retrieve messages for the specified group
            string response = retrieveMessagesForGroup(groupID);
            sendMessageToSocket(clientSocket, response);
            logMessage("INFO", "Sent GETMSGS response for group " + groupID + ": " + response);
        } else {
            string response = "ERROR: GETMSGS command format invalid.";
            sendMessageToSocket(clientSocket, response);
            logMessage("ERROR", response);
        }

    } else {
        string response = "ERROR: Unknown command received.";
        sendMessageToSocket(clientSocket, response);
        logMessage("ERROR", "Sent ERROR response: " + response);
    }
}




// Function to receive response from another server and print it
string receiveResponseFromServer(int server_socket) {
    string response = receiveMessageFromSocket(server_socket);  // Receive the raw response
    return response;
}

// Function to process the server response, split it by semicolons, and print
// void processServerResponse(const string& response) {
//    if (!response.empty()) {
//         cout << "Received response from server:" << endl;
        
//         // Split the response by semicolons and print each part on a new line
//         vector<string> responseLines = splitString(response, ';');
//         for (const string& line : responseLines) {
//             cout << line << endl;  // Print each line of the response
//         }
//     } else {
//         cerr << "No response or connection closed by the server." << endl;
//     }
// }


// Function to accept new connections and add them to the poll fds
void acceptConnections(int server_socket, vector<pollfd>& fds) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Accept the incoming connection
    int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket < 0) {
        perror("Accept failed");
        return;
    }

    // Print out the IP address of the client
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    cout << "Accepted new connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << endl;

    // Add the new client to the poll fds
    pollfd new_client_fd;
    new_client_fd.fd = client_socket;
    new_client_fd.events = POLLIN;  // We are interested in reading from this client
    fds.push_back(new_client_fd);

    // Log the new connection
    logMessage("INFO", "New connection accepted from " + string(client_ip) + ":" + to_string(ntohs(client_addr.sin_port)));
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

    // Polling setup for incoming connections
    pollfd server_fd;
    server_fd.fd = listenSock;
    server_fd.events = POLLIN;
    fds.push_back(server_fd);

    // Instructor's IP address and port number
    string instructorsIP = "130.208.246.249";
    int instructorsPort = 5002;

    // Step 1: Connect to the instructor server
    int server_socket = connectToServer(instructorsIP, instructorsPort);
    if (server_socket < 0) {
        cerr << "Failed to connect to instructor server. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    // Step 2: Add the instructor server's socket to the poll fds vector for continuous monitoring
    pollfd instructor_fd;
    instructor_fd.fd = server_socket;
    instructor_fd.events = POLLIN;
    fds.push_back(instructor_fd);

    // Start the keep-alive thread
    thread keepAliveThread(sendKeepAlive);
    keepAliveThread.detach();  // Detach to run independently
    
    cout << "Server is running, waiting for connections..." << endl;

    // Main polling loop for handling incoming commands and connections
    while (true) {
        int poll_count = poll(fds.data(), fds.size(), POLL_TIMEOUT);
        if (poll_count < 0) {
            perror("Poll failed");
            break;
        }

        // Check for new incoming connections
        if (fds[0].revents & POLLIN) {
            acceptConnections(listenSock, fds);
        }

        // Process commands from all connected sockets, including the instructor server
        for (size_t i = 1; i < fds.size(); i++) {
            if (fds[i].revents & POLLIN) {
                processClientCommand(fds[i].fd, fds, port);
            }
        }
    }

    return 0;
}