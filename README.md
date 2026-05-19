<p align="center">
  <img src="https://img.shields.io/badge/version-3.2.0-blue.svg" alt="version"/>
  <img src="https://img.shields.io/badge/C++-20-blue.svg" alt="C++20"/>
  <img src="https://img.shields.io/badge/platform-Windows-0078D4.svg" alt="platform"/>
  <img src="https://img.shields.io/badge/compiler-MSVC%20%7C%20clang--cl-orange.svg" alt="compiler"/>
  <img src="https://img.shields.io/badge/license-Modified%20MIT-green.svg" alt="license"/>
</p>

# CTX3 HWID Parser

Header-only C++20 library for Windows hardware fingerprinting with cross-validation and spoof detection.

## Overview

Collects hardware identifiers from multiple sources (IOCTL, WMI, SetupAPI, Registry, SMBIOS) and cross-validates them. Detects spoofing when one API returns different data than another.

Returns `Result<T>` for all operations — no exceptions, no silent failures. All Win32/HRESULT errors are captured with context.

**Key features:**
- Header-only, drop `chp3.hpp` into your project
- C++20 concepts, `std::format`, `std::span`
- RAII wrappers for all Windows resources
- SHA-256 via BCrypt for fingerprint hashing
- Cross-validation between WMI/SMBIOS/Registry/IOCTL
- Detects MAC spoofing, unsigned drivers, test-signing mode

## Hardware Probes
| Probe | Source | Output | Notes |
|-------|--------|--------|-------|
| `CpuProbe` | `__cpuid` / `__cpuidex` | `HardwareFingerprint` | Brand string + FMS + feature masks |
| `MotherboardProbe` | SMBIOS Type 1 | `HardwareFingerprint` | Manufacturer, product, serial (WMI fallback included) |
| `BaseboardProbe` | SMBIOS Type 2 | `HardwareFingerprint` | Manufacturer, product, version, serial, asset tag |
| `SystemUuidProbe` | SMBIOS Type 1 | `HardwareFingerprint` | Endian-corrected 16-byte UUID |
| `ChassisProbe` | SMBIOS Type 3 | `ChassisProbe::Info` | Type, manufacturer, serial, asset tag |
| `MemoryProbe` | SMBIOS Type 17 | `vector<Module>` | Per-DIMM: size, speed, type, manufacturer, part number, serial |
| `BiosProbe` | SMBIOS Type 0 | `HardwareFingerprint` | Vendor, version, release date |
| `DiskProbe` | `IOCTL_STORAGE_QUERY_PROPERTY` | `SerialNumber` | Product ID + serial (WMI fallback included) |
| `NetworkProbe` | `GetAdaptersAddresses` | `vector<MacAddress>` | Ethernet + Wi-Fi only |
| `GpuProbe` | DXGI `IDXGIFactory1` | `HardwareFingerprint` | Vendor:Device:SubSys; `details()` for VRAM/LUID |
| `MonitorProbe` | SetupAPI + EDID registry | `HardwareFingerprint` | PNP ID + product code + serial |
| `TpmProbe` | TBS `Tbsi_GetDeviceInfo` | `TpmProbe::Info` | TPM version, interface type, implementation revision |
| `VolumeProbe` | `GetVolumeInformation` | `SerialNumber` | Volume serial of any drive letter |

## Anti-Spoof Probes
| Probe | Source | Output | Notes |
|-------|--------|--------|-------|
| `NvmeProbe` | `IOCTL_STORAGE_QUERY_PROPERTY` (NVMe) | `NvmeProbe::Info` | Identify Controller: serial, model, firmware, VID/SSVID |
| `HddSmartProbe` | `IOCTL_ATA_PASS_THROUGH` | `HddSmartProbe::Info` | SMART attribute table, power-on hours, temperature |
| `PciDeviceProbe` | SetupAPI + `Enum\PCI` registry | `PciDeviceProbe::Info` | Present devices + historical registry keys (hardware swap detection) |
| `UsbProbe` | SetupAPI + `Enum\USB/USBSTOR/SWD` | `UsbProbe::Info` | VID/PID enumeration + 3 historical key sets |
| `DiskRegistryProbe` | `Enum\SCSI` + `Enum\IDE` | `vector<Entry>` | All ever-connected disk registry entries |
| `MonitorRegistryProbe` | `Enum\DISPLAY` | `vector<Entry>` | All ever-connected monitor entries |
| `NetworkWmiProbe` | WMI `Win32_NetworkAdapter` | `vector<MacAddress>` | Cross-check against `GetAdaptersAddresses` |
| `NetworkRegistryProbe` | Net adapter class registry | `vector<Adapter>` | Detects `NetworkAddress` overrides (MAC spoofing) |
| `SmbiosWmiProbe` | WMI `MSSmBios_RawSMBiosTables` | `SmbiosWmiProbe::Info` | SHA-256 of raw SMBIOS blob for cross-validation |
| `InstalledDriversProbe` | `EnumDeviceDrivers` + WinTrust | `InstalledDriversProbe::Info` | Loaded kernel modules with Authenticode verification |

## OS & Security Probes
| Probe | Source | Output | Notes |
|-------|--------|--------|-------|
| `WindowsIdentityProbe` | Registry + `GetUserName` + SID | `Identity` | Product ID, computer name, user SID |
| `OsInfoProbe` | `RtlGetVersion` + registry | `OsInfoProbe::Info` | Full build number including UBR, edition, architecture |
| `InstallDateProbe` | Registry `InstallDate` | `Info` | Unix epoch + formatted UTC string |
| `TimeZoneProbe` | `GetDynamicTimeZoneInformation` | `TimeZoneProbe::Info` | Bias, key name, DST state |
| `KeyboardLayoutProbe` | `GetKeyboardLayoutList` | `KeyboardLayoutProbe::Info` | All loaded KLIDs + language IDs |
| `CodeIntegrityProbe` | `NtQuerySystemInformation` | `CodeIntegrityProbe::Info` | KMCI/UMCI/HVCI state, test-signing, debug mode |
| `SecureBootProbe` | Registry `SecureBoot\State` | `SecureBootProbe::Info` | UEFI presence, Secure Boot & setup mode flags |

## Usage

### Include
```cpp
#include "chp3.hpp"
// The header takes care of linking via #pragma comment(lib, ...) under MSVC
```

### Single Probe
Every probe returns `Result<T>`. Check before use.
```cpp
if (auto r = chp3::CpuProbe::probe(); r) {
    std::cout << "CPU: " << r->str() << "\n";
} else {
    std::cerr << "CPU probe failed: " << r.error().to_string() << "\n";
}
```

### Full Report
`HwidEngine::collect()` runs all probes and cross-validates.
```cpp
auto report = chp3::HwidEngine::collect();
if (!report) {
    std::cerr << "Fatal: " << report.error().to_string() << "\n";
    return 1;
}

// Core fingerprints
std::cout << "Hardware HWID: " << report->hardware.combined.str() << "\n";
std::cout << "Software HWID: " << report->software.combined.str() << "\n";
std::cout << "Full HWID:     " << report->full.str() << "\n";

// Integrity checks
if (report->hardware.mac_spoof_suspected()) {
    std::cout << "WARNING: MAC address spoofing detected!\n";
}

if (report->security.environment_compromised()) {
    std::cout << "WARNING: Test-signing, debug mode, or CI disabled!\n";
}

if (report->hardware.unsigned_driver_count() > 0) {
    std::cout << "WARNING: " << report->hardware.unsigned_driver_count() 
              << " unsigned kernel drivers loaded (possible BYOVD)\n";
}
```

## Build

| Requirement | Minimum |
|------------|---------|
| **Compiler** | MSVC 19.28+ (Visual Studio 2019 16.8+) or clang-cl 13+ |
| **Language standard** | `/std:c++20` |
| **Platform** | Windows 10 1803+ (some probes require later builds) |
| **Privileges** | Most probes work as a limited user; Disk SMART, NVMe queries, and Code Integrity require **Administrator** |

## Error Handling

`Result<T>` avoids exceptions. All errors include Win32/HRESULT codes.

```cpp
enum class ErrorCode : std::uint32_t {
    ok, access_denied, not_supported, device_unavailable,
    parse_error, api_failure, no_data, internal_error
};

struct Error {
    ErrorCode     code;
    std::string   message;      // e.g., "Access denied while opening \\.\PhysicalDrive0: run as Administrator."
    std::uint32_t native_code;  // Win32 or HRESULT
};
```

All Windows resources use RAII: `FileHandle`, `RegKey`, `DeviceInfoSet`, `ComPtr<T>`, `BCryptAlgorithm`.

## Project Structure

```
ctx3-hwid-parser/
├── Include/
│   └── chp3.hpp              # Main header-only library (~2600 lines)
├── src/
│   └── main.cpp              # Demo application with all probe examples
├── CMakeLists.txt            # CMake build configuration
├── README.md                 # This file
└── LICENSE                   # Modified MIT License
```

## Anti-Spoofing

**MAC Address**: Compares `GetAdaptersAddresses`, WMI, Registry. Detects `NetworkAddress` overrides.  
**Disk**: Cross-checks IOCTL, WMI, Registry.  
**SMBIOS**: SHA-256 of raw tables for tamper detection.

## Environment Integrity

**Code Integrity**: KMCI, UMCI, HVCI, test-signing, debug mode.  
**Secure Boot**: UEFI presence, Secure Boot state, Setup Mode.  
**Drivers**: Authenticode verification, unsigned driver count (BYOVD detection).

## Hardware Swap Detection

Tracks historical registry keys: `Enum\SCSI`, `Enum\USB`, `Enum\DISPLAY`, `Enum\PCI`.

## Use Cases
**Licensing**: Stable fingerprints across OS reinstalls.
```cpp
auto report = chp3::HwidEngine::collect();
std::string license_key = report->hardware.combined.str();
```

**Anti-Cheat**: Detect spoofers and tampered environments.
```cpp
if (report->hardware.mac_spoof_suspected() || 
    report->security.environment_compromised() ||
    report->hardware.unsigned_driver_count() > 50) {
    ban_user();
}
```

**Asset Management**: Track hardware inventory.
```cpp
auto gpu = chp3::GpuProbe::probe();
auto memory = chp3::MemoryProbe::probe();
auto disks = chp3::DiskRegistryProbe::probe();
```

## License

Modified MIT License with attribution requirements. See [LICENSE](./LICENSE).

- Free for personal and commercial use
- Modify as needed
- Do not rebrand or republish as your own
- Do not remove SPDX headers or version constants
- Open-source projects should reference this repository

---

**Version 3.2.0** • CTX3 Development Team
