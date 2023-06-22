#include <iostream>
#include <string>
#include "socket.h"
#include "rsa.h"
#include "aes.h"

class Tls : Socket, Provider::Aes, Provider::Rsa {
public:
    Tls(const unsigned short size = 2048) : Rsa(size) {}
    
    Tls(const std::string& public_key, const std::string& private_key) : Rsa(public_key, private_key) {}

    ~Tls() {
        close();
    }

    bool connect(const std::string& ip_address, unsigned short port) {
        Socket::connect(ip_address, port);

        // Генерация aes ключа
        Aes::create_key();

        //Запрос открытого ключа
        Socket::send("ClientHello");

        // Добавление в переменную открытого ключа сервера для работы с ним
        Rsa::set_public(Socket::receive());

        // Шифрование открытым ключом сервера aes ключа
        std::string encrypted_key = Rsa::encrypt(Aes::get_key());

        // Отправка зашифрованного aes ключа серверу
        Socket::send(encrypted_key);

        // Вывод aes ключа
        std::cout << Aes::get_key() << "\n";

        if (Aes::get_key().empty()) {
            return false;
        }
        return true;
    }

    bool accept(Tls& client) {
        Socket::accept(client);

        // Получение от клиента запроса на открытый ключ
        std::string message = client.Socket::receive();
        // Отпрака открытого ключа клиенту
        client.Socket::send(Rsa::get_public());

        // Получение aes ключа зашифрованного открытым ключом сервера
        std::string decrypted_key = client.Socket::receive();
        // Расшифровка aes ключа с помощью закрытого ключа сервера 
        std::string encrypted_key = Rsa::decrypt(decrypted_key);

        // Установка aes ключа в качестве основного ключа шифрования
        client.Aes::set_key(encrypted_key);

        // Вывод aes ключа
        std::cout << client.Aes::get_key() << "\n";

        if (Aes::get_key().empty()) {
            return false;
        }
        return true;
    }

    bool send(const std::string& data) {
        //Шифровка сообщения с помощью aes
        std::string encrypt = Aes::encrypt(data);
        std::cout << encrypt << "\n";
        return Socket::send(encrypt);
    }

    std::string receive(size_t buffer_size = 4096) {
        std::string data = Socket::receive(buffer_size);
        //Расшифровка сообщения с помощью aes
        std::string decrypt = Aes::decrypt(data);
        return decrypt;
    }

    using Socket::close;
    using Socket::listen;
    using Socket::bind;
};