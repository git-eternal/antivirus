#pragma once

#include "../globals.hpp"

#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

class Signatures
{
private:
	std::mutex mMutex{};

public:
	explicit Signatures();

	// Update/download our signatures
	//
	void Download();
};