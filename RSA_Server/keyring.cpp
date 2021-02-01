#include "keyring.h"
#include <files.h>
#include <base64.h>
#include "Base64.h"
#include <boost/filesystem.hpp>

Keyring::Keyring()
{
}

void Keyring::savePublicKey(std::string clientIP, std::string b64PublicKey)
{
	std::cout << "Saving Public Key [" << clientIP << "]" << std::endl;
	boost::filesystem::create_directory("keys/keyring");
	std::string filename = "keys/keyring/" + clientIP + ".der";

	CryptoPP::StringSource(b64PublicKey.c_str(), true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::FileSink(filename.c_str())
		)
	);
}
