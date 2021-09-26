#pragma once

#include <filesystem>
#include <thread>
#include <Windows.h>
#include <vector>
#include <mutex>
#include <string_view>
#include <functional>
#include <iostream>
#include <array>
#include <fmt/core.h>
#include <algorithm>
#include <execution>

namespace fs = std::filesystem;

namespace Constants
{
	const std::string signatureDatabaseUrl{ "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" };
	const std::string signatureDatabasePath{ "C:\\Signatures" };
}