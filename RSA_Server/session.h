#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <base64.h>
#include <vector>
using boost::asio::ip::tcp;

class server;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket, server* serverPtr);
    void start();
    void readPacket(boost::asio::const_buffer packet);
    void do_write(boost::asio::const_buffer response);

    std::string username;
    std::vector<CryptoPP::byte> aes_key_decoded;
    std::vector<CryptoPP::byte> aes_iv_decoded;
private:
    void do_read();
    void sendClientPing();

    
    tcp::socket socket_;
    enum { max_length = 4096 };
    char data_[max_length];
    const int packet_body_length;
    char packet_body[4096];
    server *serverPtr;
};