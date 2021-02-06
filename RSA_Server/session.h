#pragma once

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <base64.h>
#include <vector>

#include "json.hpp"

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
    void sendEncrypted(nlohmann::json message);
    void disconnect();
    void printMessage(std::string message);
    void kick();
    void notice(std::string notice);

	bool subscribeToRoom(std::string roomName);
	bool unsubscribeFromRoom(std::string roomName);

    std::string getUsernameB64();
    std::string getUsername();
    void setUsername(std::string username_);
private:
    void do_read();
    void sendClientPing();

    std::string username;
    std::vector<CryptoPP::byte> aes_key_decoded;
    std::vector<CryptoPP::byte> aes_iv_decoded;
    
    tcp::socket socket_;
    enum { max_length = 4096 };
    char data_[max_length];
    const int packet_body_length;
    char packet_body[4096];
    server *serverPtr;
};