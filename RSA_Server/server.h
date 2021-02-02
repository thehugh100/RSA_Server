#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <vector>
#include "keyring.h"
#include <vector>

using boost::asio::ip::tcp;

class session;

class server
{
public:
    server(boost::asio::io_context& io_context, short port);

    void loadKeys();

    Keyring* keyring;

    char* publicRSAKey;
    char* privateRSAKey;
    size_t publicKeyLength;
    size_t privateKeyLength;

    std::vector<std::shared_ptr<session>> sessions;

private:
    void do_accept();
    tcp::acceptor acceptor_;
};