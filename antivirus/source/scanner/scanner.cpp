#include "scanner.hpp"

void Scanner::ShowReport() const
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

using path_t = std::vector<std::string>;

path_t Scanner::GetFiles(const fs::path& path)
{
	path_t filePaths{};

	// Make sure we recursively iterate here
	//
	for (const auto& root : fs::recursive_directory_iterator(path))
	{
		std::string file = root.path().string();

		// Check if the file is a valid executable
		//
		if (!IsExecutableFile(file))
			continue;

		filePaths.emplace_back(file);
	}

	return filePaths;
}

void Scanner::ScanSystem()
{	
	path_t files{ GetFiles("C:\\Users") };

	for (const auto& file : files)
	{
		fmt::print("file path: {}\n", file);
	}

	fmt::print("\nGrabbed {} valid PE files\n", files.size());
}

bool Scanner::IsExecutableFile(const std::string& path)
{
	HANDLE hMapObject{};
	HANDLE hFile{};
	LPVOID lpBase{};
	PIMAGE_DOS_HEADER dosHeader{};

	// Open the (hopefully) executable file
	//
	hFile = CreateFile(
		path.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		//fmt::print("Error: Could not open file\n");
		return false;
	}

	// Map our executable to memory
	//
	hMapObject = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READONLY,
		0, 0, NULL);

	// Get the base address of executable
	//
	lpBase = MapViewOfFile(
		hMapObject,
		FILE_MAP_READ,
		0, 0, 0);

	if (!lpBase) return false;

	// Get the base address of our DOS Header
	//
	dosHeader = (PIMAGE_DOS_HEADER)lpBase;

	// Check for valid MZ Signature (0x54AD)
	//
	return(dosHeader->e_magic == IMAGE_DOS_SIGNATURE);
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

unsigned int Scanner::ExecuteYara(const std::string& command) const
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