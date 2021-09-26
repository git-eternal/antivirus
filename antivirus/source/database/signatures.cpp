#include "signatures.hpp"

Signatures::Signatures()
{
	// Download our signatures
	//
	std::thread(&Signatures::Download, this).detach();
}

void Signatures::Download()
{
	const std::lock_guard<std::mutex> lock(mMutex);

	const fs::path databasePath{ Constants::signatureDatabasePath };

	std::string downloadPath{ Constants::signatureDatabasePath + "\\signatures.zip" };

	// Create our signature database directory
	//
	if (fs::create_directory(databasePath))
		fmt::print("Storing signature database in: {}", databasePath.string());

	// Download our signatures
	//
	HRESULT result = URLDownloadToFile(
		NULL,
		Constants::signatureDatabaseUrl.c_str(),
		downloadPath.c_str(),
		0, 
		NULL);

	if (!SUCCEEDED(result))
	{
		fmt::print("Error downloading signatures: {}", GetLastError());
		return;
	}

	// Unzip the signatures
	//

}