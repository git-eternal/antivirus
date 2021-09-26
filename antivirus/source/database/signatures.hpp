#pragma once

#include "../globals.hpp"

#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

/*
1. create a way to download all our yara files (maybe an update signatures button too)
2. store the yara files in some cache somewhere, or in memory ? idk
*/

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