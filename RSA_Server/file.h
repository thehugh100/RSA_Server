#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <boost/filesystem.hpp>

class File
{
public:
	File(boost::filesystem::path filePath);
	boost::filesystem::path filePath;
	std::vector<uint8_t> data;
	std::string uid;
};