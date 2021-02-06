#include "file.h"
#include <fstream>
#include <boost/filesystem.hpp>
#include "utility.h"

File::File(boost::filesystem::path filePath)
	:filePath(filePath)
{
	uid = Utility::genUID(4);
	std::ifstream fileData(filePath.generic_string(), std::ios::binary | std::ios::ate | std::ios::in);
	data.resize(fileData.tellg());
	fileData.seekg(0, std::ios::beg);
	fileData.read((char*)data.data(), data.size());
	std::cout << "Loaded File: " << filePath.generic_string() << " [" << data.size() << " Bytes] <" << uid << ">" << std::endl;
}
