#pragma once

#include "../globals.hpp"

class Scanner
{
private:
  enum class Result : std::uint16_t
  {
    Malicious = 0, Safe
  };

public:
  void ScanSystem();
  void ScanFile(const fs::path& filePath);

  unsigned int ExecuteYara(const std::string& command);
};

inline std::unique_ptr<Scanner> scanner{};