#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <ostream>
#include <fstream>
#include "json.hpp"

#include "Base64.h"

#include "utility.h"
#include "session.h"
#include "server.h"

#include "rsa.h"
#include <osrng.h>
#include "filters.h"
#include "files.h"
#include <base64.h>
using boost::asio::ip::tcp;

int main(int argc, char* argv[])
{
    /*CryptoPP::FileSource input("keys/public-key.der", true);  
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.BERDecode(input);

    CryptoPP::FileSource input2("keys/private-key.der", true);
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.BERDecode(input2);

    std::string cipher = Utility::RSAEncrypt(publicKey, "this is the plain text, it's catchy, you like it");
    std::cout << Utility::RSADecrypt(privateKey, cipher);*/

    try
    {
        int port = 32500;
        boost::asio::io_context io_context;
        server s(io_context, port);

        std::cout << "Started server on port " << port << std::endl;

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}