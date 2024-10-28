// ===================== CLIENT =====================

/*
 * TODO: Establish connection to the server
 * Steps:
 * 1. Create a TCP socket.
 * 2. Connect to the server (IP and port will be specified).
 */

 /*
 * TODO: Implement command-line interface (CLI) for the client
 * Steps:
 * 1. Display available commands (GETMSG, SENDMSG, LISTSERVERS).
 * 2. Parse user input.
 * 3. Send corresponding command to the server.
 * 4. Wait for and display the server response.
 */

 /*
 * TODO: Send GETMSG command to server
 * Steps:
 * 1. Send the command "GETMSG,<GROUP ID>" to the server.
 * 2. Wait for the server's response (a message for the group).
 * 3. Display the message.
 */

 /*
 * TODO: Send SENDMSG command to server
 * Steps:
 * 1. Send the command "SENDMSG,<GROUP ID>,<message content>" to the server.
 * 2. The server will forward the message to the appropriate group.
 */

 /*
 * TODO: Request list of connected servers
 * Steps:
 * 1. Send the command "LISTSERVERS" to the server.
 * 2. Receive and display the list of connected servers from the server.
 */

// ===================== SHARED FUNCTIONALITIES =====================

/*
 * TODO: Define message format and parsing logic
 * Steps:
 * 1. Use SOH (0x01) for start of message and EOT (0x04) for end.
 * 2. Implement bytestuffing for escape sequences within messages.
 * 3. Create helper functions to encode and decode messages.
 */



#include <arpa/inet.h>
#include <iostream>
#include <cstring> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()

using namespace std;

// Control characters
#define SOH 0x01 // Start of Header
#define EOT 0x04 // End of Transmission
#define MAX_MSG_LEN 5000 // maximum message length

// Function to frame a message with SOH and EOT
string frameMessage(const string& message) {
    return string(1, SOH) + message + string(1, EOT);
}

// Function to unframe a message by removing SOH and EOT
string unframeMessage(const string& message) {
    if (message.length() > 1 && message[0] == SOH && message.back() == EOT) {
        return message.substr(1, message.size() - 2); // Remove SOH and EOT
    }
    return ""; // Invalid message
}

// function to connect to the server
int connectToTheServer(const string &serverIP, int serverPort) {
    int sockfd;

    // create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        cerr << "Socket creation failed...\n";
        exit(0);
    }
    // create a sockaddr_in structure
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr);

    // connect the socket
    if (connect(sockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Connection to the server failed...\n";
        close(sockfd);
        exit(0);
    }

    cout << "Connected to the server.\n";
    return sockfd;
}

// Function to send a framed message to the server
void sendCommand(int serverSocket, const string& command) {
    string framedMessage = frameMessage(command);
    if (send(serverSocket, framedMessage.c_str(), framedMessage.length(), 0) < 0) {
        perror("send failed");
    }
}

// Function to receive a unframed message from the server
string receiveCommand(int serverSocket) {
    char buffer[MAX_MSG_LEN];
    memset(buffer, 0, sizeof(buffer));

    int bytesRead = recv(serverSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        cout << "No response..." << endl;
        return "";
    }

    string unframedMessage = unframeMessage(string(buffer, bytesRead));
    return unframedMessage;
}

// function to handle SENDMSG
void sendMsg(int serverSocket) {
    string ourGroupID;
    string anotherGroupID;
    string message;

    // get the group id, the other group id and the message to send
    cout << "Our Group ID: : ";
    getline(cin, ourGroupID);

    cout << "The Other Servers Group ID: ";
    getline(cin, anotherGroupID);

    cout << "Enter The Message To Send: ";
    getline(cin, message);

    // construct and senda the message to the server
    string command = "SENDMSG, " + ourGroupID + "," + anotherGroupID + "," + message;
    sendCommand(serverSocket, command);
}

// function to handle GETMSG
void getMsg(int serverSocket) {
    string groupID;

    // get the group id
    cout << "Group ID: ";
    getline(cin, groupID);

    // construct and send the message to the server
    string command = "GETMSG, " + groupID;
    sendCommand(serverSocket, command);
}

// function to handle LISTSERVERS
void listServers(int serverSocket) {
    // send some the message LISTSERVERS to the server
    sendCommand(serverSocket, "LISTSERVERS");
}

// Client communication loop
void clientCommunication(int serverSocket) {
    while (true) {
        string command;
        cout << "Enter one of the following commands:" << endl;
        cout << "LISTSERVERS" << endl;
        cout << "GETMSG" << endl;
        cout << "SENDMSG" << endl;
        cout << "EXIT" << endl;
        cout << "Enter command: ";

        getline(cin, command);

        if (command == "EXIT") {
            cout << "Exiting client...\n";
            break;
        } else if (command == "LISTSERVERS") {
            // call the function that handles LISTSERVERS
            listServers(serverSocket);
        } else if (command == "GETMSG") {
            // call the function that handles GETMSG
            getMsg(serverSocket);
        } else if (command == "SENDMSG") {
            // call the functiont that handles SENDMSG
            sendMsg(serverSocket);
        } else {
            cout << "Invalid command. Please try again." << endl;
            continue;
        }

        // I think we can skip this part
        // Send the command to the server
       // sendCommand(serverSocket, command);

        // Receive response from the server
        string response = receiveCommand(serverSocket);
        if (!response.empty()) {
            cout << "Response from server: " << response << endl;
        } else {
            cout << "Invalid response from server." << endl;
        }
    }
}



// Main function
int main(int argc, char *argv[]) {
    // check if the right number of arguments is passed
    if (argc != 3) {
        cerr << "Usage: ./client <server_ip> <server_port>\n";
        exit(0);
    }

    string serverIP = argv[1];
    int serverPort = atoi(argv[2]);

    // connect to the server
    int sockfd = connectToTheServer(serverIP, serverPort);
    if (sockfd < 0) {
        cerr << "Failed to connect to the server. Exiting.\n";
        exit(0);
    } else {
        clientCommunication(sockfd); // Start client communication
    }
    close(sockfd);
    return 0;
}
