#include "session.h"

#include "json.hpp"
#include "Base64.h"

#include "server.h"

session::session(tcp::socket socket, server* serverPtr)
    : socket_(std::move(socket)), serverPtr(serverPtr), packet_body_length(4096)
{
}

void session::start()
{
    std::cout << "Client connected: " << socket_.remote_endpoint().address() << std::endl;
    //send public key

    nlohmann::json data;
    data["type"] = "RSA_PUB";
    data["data"] = serverPtr->pubKey;

    std::string data_json = data.dump();

    do_write(boost::asio::buffer(data_json, data_json.size()));
    std::cout << "Sent Public Key" << std::endl;
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
            std::string clientPublicKey;
            macaron::Base64::Decode(j["data"].get<std::string>(), clientPublicKey);

            std::cout << clientPublicKey << std::endl;
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
