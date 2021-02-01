#pragma once
#include <iostream>
#include <rsa.h>
#include "json.hpp"

static class Utility
{
public:
    static void AESDecryptJson(std::string cipherText, nlohmann::json& j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv);
    static void AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string &output);
    static std::string slurp(std::ifstream& in);
    static std::string sha256(std::string data);
    static void genRSAKeyPair(uint32_t size = 2048);
};