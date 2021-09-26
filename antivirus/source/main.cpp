#include "globals.hpp"
#include "database/signatures.hpp"
#include "scanner/scanner.hpp"

int main(void)
{
  Scanner::GetInstance().ScanSystem();

  std::cin.get();
}