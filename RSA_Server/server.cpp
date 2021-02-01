#include "server.h"
#include "session.h"
#include "utility.h"
#include <boost/filesystem.hpp>

server::server(boost::asio::io_context& io_context, short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
{
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

void server::do_accept()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            if (!ec)
            {
                std::make_shared<session>(std::move(socket), this)->start();
            }

            do_accept();
        });
}
