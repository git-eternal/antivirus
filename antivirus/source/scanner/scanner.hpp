#pragma once

#include "../globals.hpp"
#include "singleton.hpp"

class Scanner : public Singleton<Scanner>
{
private:
  friend class Singleton<Scanner>;

  Scanner() noexcept = default;
  Scanner(const Scanner&) = delete;
  Scanner(Scanner&&) = delete;
  Scanner& operator=(const Scanner&) = delete;
  Scanner& operator=(Scanner&&) = delete;

private:
  enum class Result : std::uint16_t
  {
    Malicious = 0, Safe
  };

  std::vector<std::string> mVulnerableDrivers{};

public:
  void ScanSystem();
  void ScanFile(const fs::path& filePath);
  void ScanDrivers();
  unsigned int ExecuteYara(const std::string& command);
};