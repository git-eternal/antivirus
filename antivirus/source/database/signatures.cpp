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
	while (true)
	{
		std::cout << Constants::signatureDatabaseUrl << '\n';

		Sleep(1000);
	}
}
