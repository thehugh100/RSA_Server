#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <vector>

using boost::asio::ip::tcp;

class server
{
public:
    server(boost::asio::io_context& io_context, short port);

    void loadKeys();

    char* publicRSAKey;
    char* privateRSAKey;
    size_t publicKeyLength;
    size_t privateKeyLength;
private:
    void do_accept();

    tcp::acceptor acceptor_;
};