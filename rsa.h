// #include<openssl/rand.h>
// #include<openssl/crypto.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
// #include<openssl/evp.h>
#include<iostream>
#include<fstream>
#include<functional>
#include<vector>

namespace Provider {
    class Rsa {
    private:
        EVP_PKEY* key = nullptr;

        template <typename Func, typename... Args> auto key_to_pem(Func&& func, Args... args) {
            BIO* key_bio = BIO_new(BIO_s_mem());

            func(key_bio, this->key, args...);

            BUF_MEM* key_buffer_ptr;
            BIO_get_mem_ptr(key_bio, &key_buffer_ptr);

            const std::string key_str(key_buffer_ptr->data, key_buffer_ptr->length);

            BIO_free(key_bio);

            return key_str;
        }

        template <typename Func> void string_to_evp(Func&& func, const std::string& key) {
            BIO* key_bio = BIO_new_mem_buf(key.c_str(), -1);

            func(key_bio, &this->key, nullptr, nullptr);

            BIO_free(key_bio);

        }

    public:
        Rsa(const unsigned short size = 2048) {
            create_keys(size);
        }
        
        Rsa(const std::string& public_key, const std::string& private_key) {
            set_public(public_key);
            set_private(private_key);
        }

        ~Rsa() {
            EVP_PKEY_free(this->key);
        }

        void set_public(const std::string& public_key_str) {
            this->string_to_evp(&PEM_read_bio_PUBKEY, public_key_str);
        }

        void set_private(const std::string& private_key_str) {
            this->string_to_evp(&PEM_read_bio_PrivateKey, private_key_str);
        }

        void create_keys(const unsigned short size = 2048) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, size);
            EVP_PKEY_keygen(ctx, &this->key);
            EVP_PKEY_CTX_free(ctx);
        }

        std::string get_public() {
            return this->key_to_pem(&PEM_write_bio_PUBKEY);
        }

        std::string get_private() {
            return this->key_to_pem(&PEM_write_bio_PrivateKey, nullptr, nullptr, 0, nullptr, nullptr);
        }

        std::string encrypt(const std::string& text) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(this->key, nullptr);
            EVP_PKEY_encrypt_init(ctx);

            size_t ciphertext_len;
            EVP_PKEY_encrypt(ctx, nullptr, &ciphertext_len, reinterpret_cast<const unsigned char*>(text.c_str()), text.size());

            std::vector<unsigned char> ciphertext(ciphertext_len);
            EVP_PKEY_encrypt(ctx, ciphertext.data(), &ciphertext_len, reinterpret_cast<const unsigned char*>(text.c_str()), text.size());

            EVP_PKEY_CTX_free(ctx);

            std::string encrypted_text(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);

            return encrypted_text;
        }

        std::string decrypt(const std::string& ciphertext) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(this->key, nullptr);
            
            EVP_PKEY_decrypt_init(ctx);

            size_t text_len;
            EVP_PKEY_decrypt(ctx, nullptr, &text_len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());

            std::vector<unsigned char> plaintext(text_len);
            EVP_PKEY_decrypt(ctx, plaintext.data(), &text_len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
            EVP_PKEY_CTX_free(ctx);

            std::string decrypted_text(reinterpret_cast<const char*>(plaintext.data()), text_len);

            return decrypted_text;
        }

        void sign_file(const std::string& input_filepath, const std::string& output_filepath) {
            std::ifstream input_file(input_filepath, std::ios::binary);

            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, this->key);

            // Чтение файла по блокам и обновление контекста подписи с данными
            constexpr size_t buffer_size = 4096;
            char buffer[buffer_size];
            while (input_file.read(buffer, buffer_size)) {
                EVP_DigestSignUpdate(md_ctx, buffer, input_file.gcount());
            }

            // Завершение подписи и получение размера подписи
            size_t signature_size;
            EVP_DigestSignFinal(md_ctx, nullptr, &signature_size);

            std::vector<unsigned char> signature(signature_size);

            input_file.clear();
            input_file.seekg(0);
            while (input_file.read(buffer, buffer_size)) {
                EVP_DigestSignUpdate(md_ctx, buffer, input_file.gcount());
            }
            EVP_DigestSignFinal(md_ctx, signature.data(), &signature_size);

            input_file.close();

            EVP_MD_CTX_free(md_ctx);

            std::ofstream output_file(output_filepath, std::ios::binary);

            // Запись подписи в выходной файл
            output_file.write(reinterpret_cast<const char*>(signature.data()), signature_size);

            // Закрытие выходного файла
            output_file.close();
        }
    };
}


int main () {
    std::string public_key = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh5/hE/ijGWVPUriPN/nD
Q6pzlqGQQJpOht2UTcCysgpwke2S6mt0gTQ0Lw2lJReNBAqZLuV6m0nDcgGPqOQN
2eIr/vBdGjQaNOAxuYVxOBqx5zSXXHshQJqGWtyiX5vZH6Djexq8x2A+J8sarjpX
DmFhDgMK/60hfOAY5ElhsEvVhOvk829x9yfzTciqa9+6VTNNHg0c5hjQrV94EmGr
vzVvxh90oHZvYvD2G7rtIMkz4oBdnSVO98ATzEjaM4ylmF73zn2SPh3a5F+caQfq
PJtmDQzTXchSn/O/WLWGelVN6vUhOaCfK4nsdWLICJ0qgsEFP8Gk46GyQYJYTZko
8wIDAQAB
-----END PUBLIC KEY-----)";

    std::string private_key = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHn+ET+KMZZU9S
uI83+cNDqnOWoZBAmk6G3ZRNwLKyCnCR7ZLqa3SBNDQvDaUlF40ECpku5XqbScNy
AY+o5A3Z4iv+8F0aNBo04DG5hXE4GrHnNJdceyFAmoZa3KJfm9kfoON7GrzHYD4n
yxquOlcOYWEOAwr/rSF84BjkSWGwS9WE6+Tzb3H3J/NNyKpr37pVM00eDRzmGNCt
X3gSYau/NW/GH3Sgdm9i8PYbuu0gyTPigF2dJU73wBPMSNozjKWYXvfOfZI+Hdrk
X5xpB+o8m2YNDNNdyFKf879YtYZ6VU3q9SE5oJ8riex1YsgInSqCwQU/waTjobJB
glhNmSjzAgMBAAECggEAFl9mZr/+T8MpmbC+V3KJJpForfGK9U0/JPpKa6UdFUep
mDkDok4FkwbEkPqEQqEm7wK8kELkvdcmOZlOVIMCUe4AafbGtPrhU9Wj/kGoEqQ8
srI3QddB/gE/pp983Z68633D6NvZRl53AmN7zD/ten7P3trbpp+txYbGNGpyhf1P
B5SngffF3Zb4+e+X/EugI2Jxsqmtjw5SgyVCCeWhu0yrN7Y73P/N3A1ncIC7rf5L
ajOQ8e7r8w0LOaEVhQrEoPy5Mw+pTCsEJaEfbc1LrF3Woo4/sdrNpfrafdLhgofX
iPd7BChrXn1hbytfthAbY7ialgpqHGiN9dbLZMH9wQKBgQC2j2wc+wV8I5WPq4KQ
XghF/C6yOm8hNDBxVn4usV2yRqhkLOYzMJuPDZI91mwF0O6PQDvwOTqir/dCqGjx
dc1y5F6Mp6oUDTdnj5oX7p1oGS6OGBboyQrBUBltHDSPDCa097ODjS9TQomS8cjG
yLUuXiGaVToEcjfFAsqzpSGBoQKBgQC+LuHcIXGo+kSivf03xkqG6YtdFTeKQJqM
P5vCTpOx138iFcqQSNCyimHhmARVDLMKif8E21YD61DZgbuzFIymYjpJfAFBz+a0
GmstsbzzDPb9gNzDPyyi+2ZHtOHI0bkAyiv/MdfREAf//gGC3IDrsJfJGSemV+s1
YyqB4iRKEwKBgQCID2R4RO3Vk3/IT/9DMZHg9w6mbr6cdJUWI2xvyGkYkWi3IG+A
/10wxOCVjdV8kDb8NNd3Nm/pCFS0LWfpbe7tDh8ZnWw4/ZCpcnFaHNDb4Mi9xl5s
qEmHwfbxRvA1HM1MWsBD71myKAj4p5MH9FZ0dFt+9r4Cyk2eW3JPaWcLgQKBgHr9
OpbvEd/jKSvNjcnZ9CxXMAccR3Si3s8/+2ynACCMae0TBpJUZJJxp2cKthKCSe7Q
2xi6919FeF2Q5l+jNGoNMACBrxZuapWiWBmOzdCoW7oI8btaSXWE+tn4geMqrWdz
VwyLoTPUGDhWfYexLbY914r3N4r9ZGB8Jusj4a/9AoGASTK0x4TlaXzDxszUN02x
IWTYM3WBX8dLxhDRveolZZGd6QZbqr5aCtN9ccBOqyCWMhqPlLdx3DH4suzHyNk6
qCFTLPPdl1MFsny/VBb0rBhVScxdF/CDPgWz8P9VhiXx5Du8P+X6S2HJ+/GwUI5v
jHuf60IOZaMVf8NLqENCvlw=
-----END PRIVATE KEY-----)";

    Provider::Rsa rsa_key(public_key, private_key);

    // std::string input_file = "input_file.txt";
    // std::string output_file = "signed_file.bin";

    // rsa_key.sign_file(input_file, output_file);
    rsa_key.create_keys();
    std::cout << rsa_key.get_public() << rsa_key.get_private();
    
    std::string text = "text";

    std::string ciphertext = rsa_key.encrypt(text);
    std::string deciphere_text = rsa_key.decrypt(ciphertext);

    std::cout << ciphertext << "\n";
    std::cout << deciphere_text << "\n";

    return 0;
}