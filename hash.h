// #include<iostream>
#include<string>
#include<openssl/evp.h>

namespace Provider {
    class Hash {
    private:
        template <typename Func> static std::string hash_string(Func&& func, const std::string& string) {
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            const EVP_MD* md = func();
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digestLen;

            EVP_DigestInit_ex(mdctx, md, nullptr);
            EVP_DigestUpdate(mdctx, string.c_str(), string.length());
            EVP_DigestFinal_ex(mdctx, digest, &digestLen);
            EVP_MD_CTX_free(mdctx);

            // Преобразование бинарного хэша в строковый формат
            char hashStr[EVP_MAX_MD_SIZE * 2 + 1];
            for (unsigned int i = 0; i < digestLen; ++i) {
                sprintf(&hashStr[i * 2], "%02x", static_cast<unsigned int>(digest[i]));
            }

            return std::string(hashStr);
        }
    public:
        static std::string md5(const std::string& string) {
            return hash_string(&EVP_md5, string);
        }

        static std::string sha1(const std::string& string) {
            return hash_string(&EVP_sha1, string);
        }
        
        static std::string sha256(const std::string& string) {
            return hash_string(&EVP_sha256, string);
        }

        static std::string sha512(const std::string& string) {
            return hash_string(&EVP_sha512, string);
        }

        static std::string sha3_256(const std::string& string) {
            return hash_string(&EVP_sha3_256, string);
        }

        static std::string sha3_512(const std::string& string) {
            return hash_string(&EVP_sha3_512, string);
        }
    };
}


// int main() {

//     std::string text = "text";
//     std::cout << Provider::hash::md5(text) << "\n";
//     std::cout << Provider::Hash::sha1(text) << "\n";
//     std::cout << Provider::Hash::sha256(text) << "\n";
//     std::cout << Provider::Hash::sha512(text) << "\n";
//     std::cout << Provider::Hash::sha3_256(text) << "\n";
//     std::cout << Provider::Hash::sha3_512(text) << "\n";
    // Provider::rsa rsa;

    // rsa.generate_rsa_keys();
    // std::cout << rsa.get_public();

//     return 0;
// }