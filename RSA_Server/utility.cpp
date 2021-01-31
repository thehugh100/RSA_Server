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

#include "modes.h"
#include "aes.h"
#include "filters.h"

#include "Base64.h"

std::string Utility::AESEncryptData_B64(std::string plaintext, std::string key16, std::string iv16)
{
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

    if (key16.size() < CryptoPP::AES::DEFAULT_KEYLENGTH)
    {
        std::cout << "Key size too small";
        return "";
    }
    if (iv16.size() < CryptoPP::AES::BLOCKSIZE)
    {
        std::cout << "IV size too small";
        return "";
    }

    for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; ++i)
    {
        key[i] = key16[i];
    }
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i)
    {
        iv[i] = iv16[i];
    }

    std::string ciphertext;

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    stfEncryptor.MessageEnd();

    return macaron::Base64::Encode(ciphertext);
}

std::string Utility::AESDecryptData_B64(std::string ciphertextb64, std::string key16, std::string iv16)
{
    if (key16.size() < CryptoPP::AES::DEFAULT_KEYLENGTH)
    {
        std::cout << "Key size too small";
        return "";
    }
    if (iv16.size() < CryptoPP::AES::BLOCKSIZE)
    {
        std::cout << "IV size too small";
        return "";
    }

    std::string decryptedtext;
    std::string ciphertext;

    macaron::Base64::Decode(ciphertextb64, ciphertext);
    CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)key16.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)iv16.c_str());
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();

    return decryptedtext;
}

std::string Utility::RSAEncrypt(CryptoPP::RSA::PublicKey publicKey, std::string plain)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);

    std::string cipher = "";

    CryptoPP::StringSource ss1(plain, true,
        new CryptoPP::PK_EncryptorFilter(rng, e,
            new CryptoPP::StringSink(cipher)
        ) // PK_EncryptorFilter
    ); // StringSource

    return cipher;
}

std::string Utility::RSADecrypt(CryptoPP::RSA::PrivateKey privateKey, std::string cipher)
{
    std::string recovered;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);

    CryptoPP::StringSource ss2(cipher, true,
        new CryptoPP::PK_DecryptorFilter(rng, d,
            new CryptoPP::StringSink(recovered)
        ) // PK_DecryptorFilter
    ); // StringSource

    return recovered;
}

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

    CryptoPP::FileSink privkeysink("keys/private-key.der");
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    CryptoPP::RSAFunction pubkey(privkey);

    CryptoPP::FileSink pubkeysink("keys/public-key.der");
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

    std::cout << "Generated Key Pair" << std::endl;
}
