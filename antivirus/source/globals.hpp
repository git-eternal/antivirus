#pragma once

#include <filesystem>
#include <thread>
#include <Windows.h>
#include <vector>
#include <mutex>
#include <string_view>
#include <functional>
#include <iostream>
#include <array>
#include <fmt/core.h>
#include <algorithm>
#include <execution>

namespace fs = std::filesystem;

namespace Constants
{
	const std::string signatureDatabaseUrl{ "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" };
	const std::string signatureDatabasePath{ "C:\\Signatures" };

  inline std::vector<std::string> vulnerableDrivers
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
}