//
// async_tcp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <ostream>
#include <fstream>

#include "json.hpp"

#include "Base64.h"

using boost::asio::ip::tcp;

std::string pubKey;
std::string priKey;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket)
        : socket_(std::move(socket))
    {
    }

    void start()
    {
        std::cout << "Client connected: " << socket_.remote_endpoint().address() << std::endl;
        //send public key

        nlohmann::json data;
        data["type"] = "RSA_PUB";
        data["data"] = pubKey;

        std::string data_json = data.dump();

        do_write(boost::asio::buffer(data_json, data_json.size()));
        std::cout << "Sent Public Key" << std::endl;
        do_read();
    }

    void readPacket(boost::asio::const_buffer packet) {
        uint32_t dataSize = 0;
        memcpy(&dataSize, packet.data(), 4);
        std::cout << "Packet Size: " << dataSize << std::endl;
        if (dataSize > packet_body_length || dataSize > packet.size()) {
            //big problem, packet too big
            std::cout << "Malformed Packet" << std::endl;
            return;
        }

        memcpy(packet_body, (const char *)packet.data() + 4, dataSize);
        std::cout << std::string(packet_body, dataSize) << std::endl;

        do_write(boost::asio::buffer(packet_body, dataSize));
    }

private:
    void do_read()
    {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
            [this, self](boost::system::error_code ec, std::size_t length)
            {
                if (!ec)
                {
                    //data_[length] = '\0';
                    //std::cout << data_ << std::endl;
                    // do_write(boost::asio::buffer(data_, length));
                    readPacket(boost::asio::buffer(data_, length));
                    do_read();
                }
                else {
                    std::cout << ec.message() << std::endl;
                }
            });
    }

    void do_write(boost::asio::const_buffer response)
    {
        uint32_t totalSize = response.size() + 4;
        char *packet = new char[totalSize];

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

    tcp::socket socket_;
    enum { max_length = 4096 };
    char data_[max_length];
    const int packet_body_length = 4096;
    char packet_body[4096];
};

class server
{
public:
    server(boost::asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket)
            {
                if (!ec)
                {
                    std::make_shared<session>(std::move(socket))->start();
                }

                do_accept();
            });
    }

    tcp::acceptor acceptor_;
};

std::string slurp(std::ifstream& in) {
    std::ostringstream sstr;
    sstr << in.rdbuf();
    return sstr.str();
}

int main(int argc, char* argv[])
{
    if (boost::filesystem::exists("keys/public-key.pem") && boost::filesystem::exists("keys/private-key.pem"))
    {
        std::ifstream pub("keys/public-key.pem", std::ios::in);
        pubKey = slurp(pub);
        pub.close();

        std::ifstream pri("keys/private-key.pem", std::ios::in);
        priKey = slurp(pri);
        pri.close();

        std::cout << "Loaded Keys" << std::endl;
    }
    else
    {
        std::cout << "No RSA key-pair Found. Shutting down.";
        exit(EXIT_FAILURE);
    }
    try
    {
        int port = 32500;
        boost::asio::io_context io_context;
        server s(io_context, port);

        std::cout << "Started server on port " << port << std::endl;

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}