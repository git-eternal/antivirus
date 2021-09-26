#include "globals.hpp"
#include "database/signatures.hpp"
#include "scanner/scanner.hpp"

int main(void)
{
  Signatures signatures{};

  Scanner::GetInstance().ScanFile("yara32.exe");
  Scanner::GetInstance().ScanFile("ttt.exe");
  Scanner::GetInstance().ScanFile("ttt.exe");

  Scanner::GetInstance().ShowReport();
  
  return std::cin.get();
}