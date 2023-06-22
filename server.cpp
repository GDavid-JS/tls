#include <iostream>
#include "tls.h"

int main() {
    Tls server;
    Tls client;

    server.bind("127.0.0.1", 8081);

    server.listen();
    server.accept(client);

    std::string message = client.receive();
    std::cout << message + "\n";
    client.send("message from server");

    client.close();
    server.close();

    return 0;
}