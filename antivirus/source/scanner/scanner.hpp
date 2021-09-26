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
  using path_t = std::vector<std::string>;

  std::mutex mMutex{};

  enum class Result : std::uint16_t
  {
    Malicious = 0, Safe
  };

  std::vector<fs::path> mMaliciousFiles{};
  std::vector<std::string> mVulnerableDrivers{};

  unsigned int mFilesScanned{};

public:
  void ScanSystem();
  bool IsExecutableFile(const std::string& path);
  void ScanFile(const fs::path& filePath);
  void ScanDrivers();
  void ShowReport() const;
  path_t GetFiles(const fs::path& path);
  unsigned int ExecuteYara(const std::string& command) const;
};