#pragma once

#include "../globals.hpp"
#include "singleton.hpp"

// For testing at the moment
//
class Timer
{
private:
  // Type aliases to make accessing nested type easier
  using clock_type = std::chrono::steady_clock;
  using second_type = std::chrono::duration<double, std::ratio<1> >;

  std::chrono::time_point<clock_type> m_beg;

public:
  Timer() : m_beg{ clock_type::now() }
  {
  }

  void reset()
  {
    m_beg = clock_type::now();
  }

  double elapsed() const
  {
    return std::chrono::duration_cast<second_type>(clock_type::now() - m_beg).count();
  }
};

class SafeThread : public std::vector<std::thread>
{
public:
  ~SafeThread()
  {
    for (auto& thread : *this)
      thread.join();
  }
};

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
  void QuarantineFile(const fs::path& path);
  //bool IsExecutableFile(const std::string& path);
  void ScanFile(const std::string& filePath);
  void ScanDrivers();
  void Report() const;
  bool IsPeFile(const std::string_view& path);
  path_t GetAllFiles(const std::string& path);
  unsigned int ExecuteYara(const std::string& command) const;
};