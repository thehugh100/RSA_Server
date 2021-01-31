#include "utility.h"
#include <sstream>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <sha.h>
#include <hex.h>

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

std::string Utility::slurp(std::ifstream& in)
{
    std::ostringstream sstr;
    sstr << in.rdbuf();
    return sstr.str();
}

std::string Utility::sha256(std::string data)
{
    CryptoPP::SHA256 hash;
    uint8_t digest[CryptoPP::SHA256::DIGESTSIZE];
    std::string message = data;

    hash.CalculateDigest(digest, (uint8_t*)message.c_str(), message.length());

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    boost::algorithm::to_lower(output);

    return output;
}

void Utility::genRSAKeyPair(uint32_t size)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction privkey;
    privkey.Initialize(rng, size);

    CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink("keys/private-key.der"));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    CryptoPP::RSAFunction pubkey(privkey);

    CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink("keys/public-key.der"));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

    std::cout << "Generated Key Pair" << std::endl;
}
