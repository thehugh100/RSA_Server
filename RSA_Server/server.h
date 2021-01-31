#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class server
{
public:
    server(boost::asio::io_context& io_context, short port);

    void loadKeys();

    std::string pubKey;
    std::string priKey;

private:
    void do_accept();

    tcp::acceptor acceptor_;
};