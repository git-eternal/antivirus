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

	std::vector<std::string> mDriverList
	{
		"VBoxUSBMon", 
    "FireStorm", 
    "WinIo", 
    "GPCIDrv", 
    "GDrv",
		"TVicPortDevice0",
    "NTIOLib_DPC", 
    "RTCore64", 
    "amdpsp",
		"IOMap", 
    "TRIXX",
    "Trufos1", 
    "A2 Direct Disk Access",
		"Memctl",	
    "NVFLASH",
    "MsIo", 
    "nvpciflt",
    "DIRECTIO37",
		"Htsysm72FB", 
    "GIO", 
    "WinRing0_1_0_1", 
    "IOBIT_WinRing0_1_3_0",
		"BtFilter", 
    "HackSysExtremeVulnerableDriver",
    "SANDRA",
		"ALSysIO",
    "NTIOLib_1_0_2",
    "0123456789abcdef123456789abcdef",
		"mhyprot2",	
    "AMDPowerProfiler0", 
    "AMDRyzenMasterDriverV16",
	};

public:
  void ScanSystem();
  void ScanFile(const fs::path& filePath);
  void ScanDrivers();
  unsigned int ExecuteYara(const std::string& command);
};