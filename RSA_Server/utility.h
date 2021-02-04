#pragma once
#include <iostream>
#include <rsa.h>
#include "json.hpp"

static class Utility
{
public:
    static const std::string ANSI_RESET;
    static const std::string ANSI_RED;
    static const std::string ANSI_GREEN;
    static const std::string ANSI_YELLOW;
    static const std::string ANSI_BLUE;
    static const std::string ANSI_MAGENTA;
    static const std::string ANSI_CYAN;
    static const std::string ANSI_CYAN_BG;
    static const std::string ANSI_WHITE;

    static void AESDecryptJson(std::string cipherText, nlohmann::json& j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv);
    static void AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string &output);
    static std::string slurp(std::ifstream& in);
    static std::string sha256(std::string data);
    static void genRSAKeyPair(uint32_t size = 2048);
};