#include "scanner.hpp"

void Scanner::ShowReport()
{
	if (mMaliciousFiles.empty())
	{
		fmt::print("No malicious files found.\n");
		return;
	}
	
	fmt::print("Malicious file(s) detected:\n");

	for (const auto& malware : mMaliciousFiles)
		fmt::print("Path: {}\n", malware.string());
}

void Scanner::ScanSystem()
{
	// TODO: Add directory iterator
	//
}

void Scanner::ScanFile(const fs::path& filePath)
{
	if (!fs::exists(filePath))
		return;

	// TODO: Add support for fast scan (-f)
	//
	unsigned int scanResult = ExecuteYara("yara32.exe -c rule.yar " + filePath.string());

	if (scanResult >= 1)
	{
		mMaliciousFiles.emplace_back(filePath);
	}	
}

unsigned int Scanner::ExecuteYara(const std::string& command)
{
	std::array<char, 128> buffer; std::string result{};

	// Create our command pipe
	//
	std::unique_ptr<FILE, decltype(&_pclose)>
		pipe(_popen(command.c_str(), "r"), _pclose);

	if (!pipe)
		throw std::runtime_error("popen() failed!");

	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}

	return std::stoi(result);
}

void Scanner::ScanDrivers()
{
	const std::lock_guard<std::mutex> lock(mMutex);

	std::for_each(std::execution::par_unseq, 
		Constants::vulnerableDrivers.begin(),
		Constants::vulnerableDrivers.end(), [&](auto& driver) -> void
	{
		std::string driverPath{ "\\\\.\\" + driver };

		// Attempt to create a handle to the specified driver
		//
		HANDLE handle = CreateFileA(driverPath.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING, 0, NULL);

		if (handle != INVALID_HANDLE_VALUE)
		{
			// Append the vulnerable driver to our list
			//
			mVulnerableDrivers.push_back(driver);
		}
	});

	if (mVulnerableDrivers.empty()) 
	{
		fmt::print("No vulnerable drivers found!");
		return;
	}

	fmt::print("Potentially vulnerable driver(s):\n");

	for (const auto& driver : mVulnerableDrivers)
		fmt::print("Device name: {}", driver);
}