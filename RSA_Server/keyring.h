#pragma once
#include <iostream>

class Keyring
{
public:
	Keyring();
	void savePublicKey(std::string clientIP, std::string b64PublicKey);
};