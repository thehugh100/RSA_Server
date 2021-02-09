#include "server.h"
#include "session.h"
#include "utility.h"
#include <boost/filesystem.hpp>
#include "Base64.h"
#include "file.h"

server::server(boost::asio::io_context& io_context, short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
{
    std::cout << Utility::ANSI_GREEN << "Started server on port " << port << Utility::ANSI_RESET << std::endl;
    keyring = new Keyring();

	auto general = new Room("General");
	general->files.emplace_back(new File("files/photos.zip"));
	general->files.emplace_back(new File("files/HeidiSQL.exe"));

    rooms.emplace_back(general);
    rooms.emplace_back(new Room("Room_1"));
	rooms.emplace_back(new Room("Room_2"));

    loadKeys();
    do_accept();
}

void server::loadKeys()
{
    if (boost::filesystem::exists("keys/public-key.der") && boost::filesystem::exists("keys/private-key.der"))
    {
        std::ifstream pub("keys/public-key.der", std::ios::binary | std::ios::ate);
        publicKeyLength = pub.tellg();
        pub.seekg(0, std::ios::beg);
        publicRSAKey = new char[publicKeyLength];
        if (!pub.read(publicRSAKey, publicKeyLength))
        {
            std::cout << "Failed to load public key." << std::endl;
        }
        pub.close();

        std::ifstream priv("keys/private-key.der", std::ios::binary | std::ios::ate);
        privateKeyLength = priv.tellg();
        priv.seekg(0, std::ios::beg);
        privateRSAKey = new char[privateKeyLength];
        if (!priv.read(privateRSAKey, privateKeyLength))
        {
            std::cout << "Failed to load private key." << std::endl;
        }
        priv.close();
        std::cout << "Loaded Key Pair" << std::endl;
    }
    else
    {
        Utility::genRSAKeyPair(2048);
        loadKeys();
    }
}

void server::getOnlineUsers(nlohmann::json& online)
{
    online["type"] = "online";
    for (auto& i : sessions)
    {
        online["users"].push_back(i->getUsernameB64());
    }
}

void server::getRooms(nlohmann::json& rooms_)
{
    rooms_["type"] = "rooms";
    for (auto& i : rooms)
    {
        rooms_["rooms"].push_back(i->getNameB64());
    }
}

void server::notice(std::string notice)
{
    std::cout << "Sending Notice: " << notice << std::endl;
    for (auto& i : sessions)
    {
        i->notice(notice);
    }
}

void server::do_accept()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            if (!ec)
            {
                auto sessionPtr = std::make_shared<session>(std::move(socket), this);
                sessions.emplace_back(sessionPtr);
                sessionPtr->start();
            }

            do_accept();
        });
}
