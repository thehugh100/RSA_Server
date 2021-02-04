#include "room.h"
#include "session.h"
#include "Base64.h"

Room::Room(std::string name)
	:name(name)
{

}

void Room::sendToAllEncrypted(nlohmann::json message)
{
	for (auto& i : sessions)
		i->sendEncrypted(message);
}

void Room::subscribe(std::shared_ptr<session> session)
{
	session->printMessage("<Subscribed to " + name + ">");
	sessions.emplace_back(session);

	sendToAllEncrypted({ {"type", "notice"}, {"data", macaron::Base64::Encode(session->getUsername() + " Joined") } });
}

void Room::unSubscribe(std::shared_ptr<session> session)
{
	session->printMessage("<Unsubscribed from " + name + ">");
	auto it = std::find(sessions.begin(), sessions.end(), session);
	sessions.erase(it);

	sendToAllEncrypted({ {"type", "notice"}, {"data", macaron::Base64::Encode(session->getUsername() + " Left") } });
}
