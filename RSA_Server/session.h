#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket);
    void start(std::string pub, std::string priv);
    void readPacket(boost::asio::const_buffer packet);

    std::string pubKey;
    std::string priKey;

private:
    void do_read();

    void do_write(boost::asio::const_buffer response);

    tcp::socket socket_;
    enum { max_length = 4096 };
    char data_[max_length];
    const int packet_body_length;
    char packet_body[4096];
};