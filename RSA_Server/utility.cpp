#include "utility.h"
#include <sstream>
#include <fstream>

std::string Utility::slurp(std::ifstream& in)
{
    std::ostringstream sstr;
    sstr << in.rdbuf();
    return sstr.str();
}
