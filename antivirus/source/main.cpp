#include "globals.hpp"
#include "database/signatures.hpp"

class Scanner
{
public:
	void ScanSystem();
	void ScanFile(const fs::path& filePath);
};

int main(void)
{
	Signatures s;
	Signatures t;

	std::cin.get();
}