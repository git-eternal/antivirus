#pragma once

#include "../globals.hpp"

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>


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