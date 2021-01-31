#pragma once
#include <iostream>

static class Utility
{
public:
    static std::string slurp(std::ifstream& in);
    static std::string sha256(std::string data);
    static void genRSAKeyPair(uint32_t size = 2048);
};