#pragma once

#include <filesystem>
#include <thread>
#include <Windows.h>
#include <vector>
#include <mutex>
#include <string_view>
#include <functional>
#include <iostream>

namespace fs = std::filesystem;

namespace Constants
{
	const std::string_view signatureDatabaseUrl{ "url" };
}