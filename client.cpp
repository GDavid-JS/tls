#include <iostream>
#include "tls.h"

int main() {
    Tls client;
    client.connect("127.0.0.1", 8081);
    

    client.send("message from client");

    std::string response = client.receive();
    std::cout << response << "\n";

    client.close();

    return 0;
}
