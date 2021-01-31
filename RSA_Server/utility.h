#pragma once
#include <iostream>
#include <rsa.h>

static class Utility
{
public:
    static std::string AESEncryptData_B64(std::string plaintext, std::string key16, std::string iv16);
    static std::string AESDecryptData_B64(std::string ciphertextb64, std::string key16, std::string iv16);

    static std::string RSAEncrypt(CryptoPP::RSA::PublicKey publicKey, std::string plain);
    static std::string RSADecrypt(CryptoPP::RSA::PrivateKey privateKey, std::string cipher);

    static std::string slurp(std::ifstream& in);
    static std::string sha256(std::string data);
    static void genRSAKeyPair(uint32_t size = 2048);
};