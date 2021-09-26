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

	// Download our signatures
	//

	const fs::path databasePath{ "C:\\Signatures" };

	// Create our signature database directory
	//
	if (fs::create_directory(databasePath))
		fmt::print("storing signature database in: {}", 
								databasePath.string());


}