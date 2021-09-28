#include "globals.hpp"
#include "database/signatures.hpp"
#include "scanner/scanner.hpp"

int main(void)
{
	// Raise our process priority to realtime
	//
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

  Scanner::GetInstance().ScanSystem();

  std::cin.get();
}