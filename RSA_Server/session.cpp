#include "session.h"

#include "json.hpp"
#include "Base64.h"

#include "server.h"
#include "utility.h"

#include <rsa.h>
#include <files.h>
#include <base64.h>
#include <osrng.h>
#include <aes.h>
#include <filters.h>
#include "modes.h"

session::session(tcp::socket socket, server* serverPtr)
    : socket_(std::move(socket)), serverPtr(serverPtr), packet_body_length(4096)
{
    aes_iv_decoded.resize(16);
    aes_key_decoded.resize(16);
}

void session::start()
{
    std::cout << "Client connected: " << socket_.remote_endpoint().address() << std::endl;
    //send public key

    nlohmann::json data;
    data["type"] = "welcome";
    std::string publicKeyStr(serverPtr->publicRSAKey, serverPtr->publicKeyLength);
    std::string publicKeyB64 = macaron::Base64::Encode(publicKeyStr);

    data["data"] = publicKeyB64;

    std::string data_json = data.dump();

    do_write(boost::asio::buffer(data_json, data_json.size()));
    std::cout << "\tSent Welcome Message" << std::endl;
    std::cout << "\tPublic Key Length: " << serverPtr->publicKeyLength;
    do_read();
}

void session::readPacket(boost::asio::const_buffer packet)
{
    uint32_t dataSize = 0;
    memcpy(&dataSize, packet.data(), 4);
    //std::cout << "Packet Size: " << dataSize << std::endl;
    if (dataSize > packet_body_length || dataSize > packet.size())
    {
        //big problem, packet too big
        std::cout << "Malformed Packet" << std::endl;
        return;
    }

    memcpy(packet_body, (const char*)packet.data() + 4, dataSize);
    std::cout << std::string(packet_body, dataSize) << std::endl;

    try
    {
        nlohmann::json j = nlohmann::json::parse(std::string(packet_body, dataSize));

        if (j["type"] == "announce")
        {
            std::string aes_keyb64 = j["aes_key"];
            std::string aes_ivb64 = j["aes_iv"];

            std::vector<CryptoPP::byte> aes_key_rsa;
            aes_key_rsa.resize(256);
            std::vector<CryptoPP::byte> aes_iv_rsa;
            aes_iv_rsa.resize(256);

            CryptoPP::StringSource decryptor((CryptoPP::byte*) aes_keyb64.c_str(), aes_keyb64.size(), true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::ArraySink(aes_key_rsa.data(), aes_key_rsa.size())
                ));

            CryptoPP::StringSource decryptor2((CryptoPP::byte*) aes_ivb64.c_str(), aes_ivb64.size(), true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::ArraySink(aes_iv_rsa.data(), aes_iv_rsa.size())
                ));

            CryptoPP::StringSource privateKeySS((const CryptoPP::byte* )serverPtr->privateRSAKey, serverPtr->privateKeyLength, true);
            CryptoPP::RSA::PrivateKey privateKey;
            privateKey.BERDecode(privateKeySS);

            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
            d.Decrypt(rng, aes_key_rsa.data(), aes_key_rsa.size(), aes_key_decoded.data());
            d.Decrypt(rng, aes_iv_rsa.data(), aes_iv_rsa.size(), aes_iv_decoded.data());

            nlohmann::json ready;
            ready["type"] = "crypt";

            nlohmann::json cryptDat;
            cryptDat["token"] = "this is the token";
            cryptDat["other data"] = "this is even more data";

            std::string cryptText;
            Utility::AESEcryptJson(cryptDat, aes_key_decoded, aes_iv_decoded, cryptText);

            ready["data"] = cryptText;

            std::string readyMessage = ready.dump();
            do_write(boost::asio::buffer(readyMessage.c_str(), readyMessage.size()));

        }
        if (j["type"] == "echo")
        {
            do_write(boost::asio::buffer(packet_body, dataSize));
        }
    }
    catch (nlohmann::json::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
}

void session::do_read()
{
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                readPacket(boost::asio::buffer(data_, length));
                do_read();
            }
            else {
                std::cout << ec.message() << std::endl;
            }
        });
}

void session::do_write(boost::asio::const_buffer response)
{
    uint32_t totalSize = response.size() + 4;
    char* packet = new char[totalSize];

    uint32_t size = response.size();
    memcpy(&packet[0], &size, 4);
    memcpy(&packet[4], response.data(), size);

    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(packet, totalSize),
        [this, self, packet](boost::system::error_code ec, std::size_t /*length*/)
        {
            if (!ec)
            {
            }
            delete[] packet;
        });
}
