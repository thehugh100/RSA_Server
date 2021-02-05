#include "room.h"
#include "session.h"
#include "Base64.h"

Room::Room(std::string name)
	:name(name)
{
	std::cout << "Created Room: " << name << std::endl;
}

std::string Room::getName()
{
	return name;
}

std::string Room::getNameB64()
{
	return macaron::Base64::Encode(name);
}

void Room::sendToAllEncrypted(nlohmann::json message, std::shared_ptr<session> ignore)
{
	for (auto& i : sessions)
	{
		if(ignore != i)
			i->sendEncrypted(message);
	}
}

void Room::subscribe(std::shared_ptr<session> session)
{
	session->printMessage("<Subscribed to " + name + ">");
	sessions.emplace_back(session);

	sendToAllEncrypted({ {"type", "notice"}, {"data", macaron::Base64::Encode(session->getUsername() + " Joined") } }, session);
}

void Room::unSubscribe(std::shared_ptr<session> session)
{
	session->printMessage("<Unsubscribed from " + name + ">");
	auto it = std::find(sessions.begin(), sessions.end(), session);
	sessions.erase(it);

	sendToAllEncrypted({ {"type", "notice"}, {"data", macaron::Base64::Encode(session->getUsername() + " Left") } }, session);
}
