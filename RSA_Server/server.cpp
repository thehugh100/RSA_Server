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
    if (boost::filesystem::exists("keys/public-key.pem") && boost::filesystem::exists("keys/private-key.pem"))
    {
        std::ifstream pub("keys/public-key.pem", std::ios::in);
        pubKey = Utility::slurp(pub);
        pub.close();

        std::ifstream pri("keys/private-key.pem", std::ios::in);
        priKey = Utility::slurp(pri);
        pri.close();

        std::cout << "Loaded Keys" << std::endl;
    }
    else
    {
        std::cout << "No RSA key-pair Found. Shutting down.";
        exit(EXIT_FAILURE);
    }
}

void server::do_accept()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            if (!ec)
            {
                std::make_shared<session>(std::move(socket))->start(pubKey, priKey);
            }

            do_accept();
        });
}
