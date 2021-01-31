#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class server;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket, server* serverPtr);
    void start();
    void readPacket(boost::asio::const_buffer packet);

private:
    void do_read();

    void do_write(boost::asio::const_buffer response);

    tcp::socket socket_;
    enum { max_length = 4096 };
    char data_[max_length];
    const int packet_body_length;
    char packet_body[4096];
    server *serverPtr;
};