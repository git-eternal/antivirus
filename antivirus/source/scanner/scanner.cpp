#include "scanner.hpp"

void Scanner::ScanFile(const fs::path& filePath)
{
  if (!fs::exists(filePath))
    return;

  // TODO: Add support for fast scan (-f)
  //
  unsigned int scanResult = ExecuteYara("yara32.exe -c rule.yar " + filePath.string());

  if (scanResult >= 1)
    std::cout << "malicious\n";
  else
    std::cout << "not malicious\n";
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