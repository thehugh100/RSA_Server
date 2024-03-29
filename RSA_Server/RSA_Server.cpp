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
    #if defined WIN32 || defined _WIN32 || defined WIN64 || defined _WIN64
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    #endif
    try
    {
        int port = 32500;
        boost::asio::io_context io_context;
        server s(io_context, port);

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}