#pragma once
#include <iostream>
#include <rsa.h>

static class Utility
{
public:
    static std::string AESEncryptData_B64(std::string plaintext, std::string key16, std::string iv16);
    static std::string AESDecryptData_B64(std::string ciphertextb64, std::string key16, std::string iv16);

    static void RSAEncrypt(CryptoPP::RSA::PublicKey publicKey, CryptoPP::byte* plaintext, size_t plaintextLength, CryptoPP::byte* cipherText);
    static size_t RSADecrypt(CryptoPP::RSA::PrivateKey privateKey, CryptoPP::byte* cipher, size_t cipherLength, CryptoPP::byte* plaintext);

    static std::string slurp(std::ifstream& in);
    static std::string sha256(std::string data);
    static void genRSAKeyPair(uint32_t size = 2048);
};