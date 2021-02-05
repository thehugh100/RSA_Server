#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <vector>

#include "keyring.h"
#include "json.hpp"
#include "room.h"

using boost::asio::ip::tcp;

class session;

class server
{
public:
    server(boost::asio::io_context& io_context, short port);
    void loadKeys();

    void getOnlineUsers(nlohmann::json& online);
    void getRooms(nlohmann::json& rooms_);
    void notice(std::string notice);

    Keyring* keyring;
    char* publicRSAKey;
    char* privateRSAKey;
    size_t publicKeyLength;
    size_t privateKeyLength;

    std::vector<std::shared_ptr<session>> sessions;
    std::vector<std::shared_ptr<Room>> rooms;
private:
    void do_accept();
    tcp::acceptor acceptor_;
};