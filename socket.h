#include <string>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class Socket {
private:
    int socket_id = -1;
    int ip;
    int tcp;

public:
    Socket(int ip = AF_INET, int tcp = SOCK_STREAM) {
        this->ip = ip;
        this->tcp = tcp;

        #ifdef _WIN32
            socket_id = INVALID_SOCKET;

            WSADATA wsa_data;
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
                throw std::runtime_error("Failed to initialize Winsock");
            }
        #endif

        socket_id = socket(this->ip, this->tcp, 0);
    }

    ~Socket() {
        close();
    }

    bool bind(const std::string& ip_address, unsigned short port) {
        sockaddr_in socketAddress{};
        socketAddress.sin_family = this->ip;
        socketAddress.sin_addr.s_addr = inet_addr(ip_address.c_str());
        socketAddress.sin_port = htons(port);

        #ifdef _WIN32
            return ::bind(socket_id, reinterpret_cast<struct sockaddr*>(&socketAddress), sizeof(socketAddress)) != SOCKET_ERROR;
        #else
            return ::bind(socket_id, reinterpret_cast<struct sockaddr*>(&socketAddress), sizeof(socketAddress)) != -1;
        #endif
    }

    bool listen(int maxConnections = 5) {
        return ::listen(socket_id, maxConnections) != -1;
    }

    bool accept(Socket& clientSocket) {
        int clientSocketId;
        sockaddr_in clientSocketAddress{};

        #ifdef _WIN32
            int clientSocketAddressLength = sizeof(clientSocketAddress);
        #else
            socklen_t clientSocketAddressLength = sizeof(clientSocketAddress);
        #endif

        clientSocketId = ::accept(socket_id, reinterpret_cast<struct sockaddr*>(&clientSocketAddress), &clientSocketAddressLength);

        #ifdef _WIN32
            if (clientSocketId == INVALID_SOCKET) {
                return false;
            }
        #else
            if (clientSocketId == -1) {
                return false;
            }
        #endif

        clientSocket.socket_id = clientSocketId;
        return true;
    }

    bool connect(const std::string& ip_address, unsigned short port) {
        sockaddr_in server_socket_address{};
        server_socket_address.sin_family = this->ip;
        server_socket_address.sin_addr.s_addr = inet_addr(ip_address.c_str());
        server_socket_address.sin_port = htons(port);

        #ifdef _WIN32
            return ::connect(socket_id, reinterpret_cast<struct sockaddr*>(&server_socket_address), sizeof(server_socket_address)) != INVALID_SOCKET;
        #else
            return ::connect(this->socket_id, reinterpret_cast<struct sockaddr*>(&server_socket_address), sizeof(server_socket_address)) != -1;
        #endif
    }

    bool send(const std::string& data) {
        ssize_t bytes_sent = ::send(socket_id, reinterpret_cast<const char*>(data.data()), data.size(), 0);

        #ifdef _WIN32
            return bytes_sent != SOCKET_ERROR;
        #else
            return bytes_sent != -1;
        #endif
    }

    std::string receive(size_t buffer_size = 4096) {
        std::vector<char> buffer(buffer_size);
        ssize_t bytes_read = ::recv(socket_id, buffer.data(), buffer_size - 1, 0);
        if (bytes_read <= 0) {
            return "";
        }
        return std::string(buffer.data(), bytes_read);
    }

    void close() {
        #ifdef _WIN32
            if (socket_id != INVALID_SOCKET) {
                ::closesocket(socket_id);
                socket_id = INVALID_SOCKET;
            }
            WSACleanup();
        #else
            ::close(socket_id);
            socket_id = -1;
        #endif
    }
};