#include "session.h"

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
#include <algorithm>

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

    sendClientPing();

    std::cout << "\tSent Welcome Message" << std::endl;
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

    try
    {
        nlohmann::json j = nlohmann::json::parse(std::string(packet_body, dataSize));

        if (j["type"] == "announce")
        {
            printMessage("<announce>");
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

            if (j.contains("crypt"))
            {
                nlohmann::json clientCrypt;
                Utility::AESDecryptJson(j["crypt"], clientCrypt, aes_key_decoded, aes_iv_decoded);
                serverPtr->keyring->savePublicKey(socket_.remote_endpoint().address().to_string(), clientCrypt["public_key"]);

                if (clientCrypt.contains("username"))
                {
                    macaron::Base64::Decode(clientCrypt["username"], username);
                    std::cout << username << " connected" << std::endl;
                    sendEncrypted({ {"type", "announce_response"}, "data", "OK" });
                }
                else
                {
                    std::cout << "Invalid announce, username not provided" << std::endl;
                    sendEncrypted({ {"type", "announce_response"}, "data", "Invalid Username" });
                }
            }
        }
        if (j["type"] == "crypt")
        {
            nlohmann::json clientCrypt;
            Utility::AESDecryptJson(j["data"], clientCrypt, aes_key_decoded, aes_iv_decoded);

            if (clientCrypt["type"] == "online")
            {
                nlohmann::json online;
                serverPtr->getOnlineUsers(online);

                sendEncrypted(online);
            }
            if (clientCrypt["type"] == "message")
            {
                std::cout << clientCrypt.dump() << std::endl;
                std::string to;
                std::string message;
                macaron::Base64::Decode(clientCrypt["to"], to);
                macaron::Base64::Decode(clientCrypt["data"], message);

                for (auto& i : serverPtr->sessions)
                {
                    if (i->username == to)
                    {                       
                        nlohmann::json from;
                        from["type"] = "message";
                        from["from"] = macaron::Base64::Encode(username);
                        from["data"] = clientCrypt["data"];

                        i->sendEncrypted(from);
                    }
                }
            }
        }
        if (j["type"] == "ping")
        {
            if (j.contains("ts"))
            {
                uint64_t ts_ = j["ts"];
                uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                std::cout << "Client latency: " << (ms - ts_) / 2 << " ms" << std::endl;
            }
        }
        if (j["type"] == "cping")
        {
            std::cout << "cping" << std::endl;
            do_write(boost::asio::buffer(packet_body, dataSize));
        }
        if (j["type"] == "echo")
        {
            std::string data;
            macaron::Base64::Decode(j["data"], data);

            std::cout << "echo: [" << data << "] "<< std::endl;

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
                std::cout << socket_.remote_endpoint().address().to_string() << ": " << ec.message() << " [" << ec.value() << "]" << std::endl;
                if ((boost::asio::error::eof == ec) || (boost::asio::error::connection_reset == ec))
                {
                    disconnect();
                }
            }
        });
}

void session::sendClientPing()
{
    uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
        ).count();
    nlohmann::json ts;
    ts["type"] = "ping";
    ts["ts"] = ms;
    std::string pingcmd = ts.dump();
    do_write(boost::asio::buffer(pingcmd.c_str(), pingcmd.size()));
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

void session::sendEncrypted(nlohmann::json message)
{
    std::string crypt;
    Utility::AESEcryptJson(message, aes_key_decoded, aes_iv_decoded, crypt);

    nlohmann::json cData;
    cData["type"] = "crypt";
    cData["data"] = crypt;

    std::string messageComposed = cData.dump();
    do_write(boost::asio::buffer(messageComposed.c_str(), messageComposed.size()));
}

void session::disconnect()
{
    auto it = std::find(serverPtr->sessions.begin(), serverPtr->sessions.end(), shared_from_this());
    serverPtr->sessions.erase(it);
}

void session::printMessage(std::string message)
{
    std::string name;
    if (!username.empty())
        name = username;
    else
        name = socket_.remote_endpoint().address().to_string();

    std::cout << "[" << name << "]: " << message << std::endl;
}

void session::kick()
{
    sendEncrypted({ {"type", "notice"}, {"data", macaron::Base64::Encode("You have been kicked from the server.")}});
    disconnect();
    socket_.close();
}

std::string session::getUsernameB64()
{
    return macaron::Base64::Encode(getUsername());
}

std::string session::getUsername()
{
    if (username.empty())
    {
        printMessage("Tried to get username of client but it's not set.");
    }
    return username;
}

void session::setUsername(std::string username_)
{
    username = username_;
}
