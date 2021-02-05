#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "json.hpp"

class session;

class Room
{
public:
	Room(std::string name);
	std::vector<std::shared_ptr<session>> sessions;

	std::string getName();
	std::string getNameB64();

	void sendToAllEncrypted(nlohmann::json message, std::shared_ptr<session> ignore = nullptr);
	void subscribe(std::shared_ptr<session> session);
	void unSubscribe(std::shared_ptr<session> session);
private:
	std::string name;
};