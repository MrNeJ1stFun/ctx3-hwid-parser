<p align="center">
  <img src="https://img.shields.io/badge/version-3.1.0-blue.svg" alt="version"/>
  <img src="https://img.shields.io/badge/C++-20-blue.svg" alt="C++20"/>
  <img src="https://img.shields.io/badge/platform-Windows-0078D4.svg" alt="platform"/>
  <img src="https://img.shields.io/badge/compiler-MSVC%20%7C%20clang--cl-orange.svg" alt="compiler"/>
  <img src="https://img.shields.io/badge/license-Modified%20MIT-green.svg" alt="license"/>
</p>

<h1 align="center">CTX3 HWID Parser & Environment Integrity Engine</h1>

<p align="center">
  <strong>A modern, header-only C++20 engine for hardware fingerprinting, cross-validation, and anti-tamper detection on Windows.</strong>
</p>

---

## 📋 Overview

**ctx3-hwid-parser** goes beyond traditional hardware ID collection. While it provides robust, cryptographically hashed hardware fingerprints (SHA-256 via CNG/BCrypt), its core strength lies in **Environment Integrity**. 

In modern licensing and anti-cheat scenarios, a simple HWID string is trivially bypassed by kernel-level spoofers. CTX3 counters this by querying multiple OS subsystems (IOCTL, WMI, SetupAPI, Registry, SMBIOS) and cross-validating the results. If a spoofer hooks one API but forgets another, CTX3 detects the discrepancy and flags the environment.

Every probe returns a strongly-typed `Result<T>` — either the requested data or a structured `Error` with Win32/HRESULT context — ensuring failures are never silent.

### 🎯 Design Principles

| Principle | Detail |
|-----------|--------|
| **Header-Only** | Drop `chp3.hpp` into your project. No .cpp files, no CMake dependencies required. |
| **Modern C++20** | Leverages Concepts, `std::format`, `std::span`, and structured bindings. |
| **Structured Errors** | `Result<T>` with `ErrorCode`, human-readable messages, and native OS error codes. |
| **RAII Everywhere** | `FileHandle`, `RegKey`, `DeviceInfoSet`, `ComPtr<T>` — zero resource leaks. |
| **Probe Independence** | Each probe is a standalone class satisfying the `Probe` concept. Use one, use all, or compose your own. |
| **Defence in Depth** | Cross-validation between WMI, SMBIOS, Registry, and IOCTL sources. Built-in spoof and integrity detection. |

---

## 🔍 Feature Matrix

### Core Hardware Probes (Identity)
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

### Tier 2: Correlation & Anti-Spoof Probes (Integrity)
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

### Tier 3: OS & Security Probes (Environment)
| Probe | Source | Output | Notes |
|-------|--------|--------|-------|
| `WindowsIdentityProbe` | Registry + `GetUserName` + SID | `Identity` | Product ID, computer name, user SID |
| `OsInfoProbe` | `RtlGetVersion` + registry | `OsInfoProbe::Info` | Full build number including UBR, edition, architecture |
| `InstallDateProbe` | Registry `InstallDate` | `Info` | Unix epoch + formatted UTC string |
| `TimeZoneProbe` | `GetDynamicTimeZoneInformation` | `TimeZoneProbe::Info` | Bias, key name, DST state |
| `KeyboardLayoutProbe` | `GetKeyboardLayoutList` | `KeyboardLayoutProbe::Info` | All loaded KLIDs + language IDs |
| `CodeIntegrityProbe` | `NtQuerySystemInformation` | `CodeIntegrityProbe::Info` | KMCI/UMCI/HVCI state, test-signing, debug mode |
| `SecureBootProbe` | Registry `SecureBoot\State` | `SecureBootProbe::Info` | UEFI presence, Secure Boot & setup mode flags |

---

## 🚀 Quick Start

### 1. Include the header
```cpp
#include "chp3.hpp"
// The header takes care of linking via #pragma comment(lib, ...) under MSVC
```

### 2. Individual Probes
Every probe returns `Result<T>`. Always check before use.
```cpp
if (auto r = chp3::CpuProbe::probe(); r) {
    std::cout << "CPU: " << r->str() << "\n";
} else {
    std::cerr << "CPU probe failed: " << r.error().to_string() << "\n";
}
```

### 3. Aggregated Report & Trust Evaluation
Use `HwidEngine::collect()` to run all probes, cross-validate, and generate SHA-256 digests.
```cpp
auto report = chp3::HwidEngine::collect();
if (!report) {
    std::cerr << "Fatal: " << report.error().to_string() << "\n";
    return 1;
}

// Core HWID strings
std::cout << "Hardware HWID: " << report->hardware.combined.str() << "\n";
std::cout << "Software HWID: " << report->software.combined.str() << "\n";
std::cout << "Full HWID:     " << report->full.str() << "\n";

// Anti-spoof & Integrity checks built into the report
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

---

## ⚙️ Build Requirements

| Requirement | Minimum |
|------------|---------|
| **Compiler** | MSVC 19.28+ (Visual Studio 2019 16.8+) or clang-cl 13+ |
| **Language standard** | `/std:c++20` |
| **Platform** | Windows 10 1803+ (some probes require later builds) |
| **Privileges** | Most probes work as a limited user; Disk SMART, NVMe queries, and Code Integrity require **Administrator** |

---

## 🏗️ Architecture & Error Handling

The library uses a custom `Result<T>` type (similar to Rust's `Result` or C++23's `std::expected`) to avoid exceptions on the hot path.

```cpp
enum class ErrorCode : std::uint32_t {
    ok, access_denied, not_supported, device_unavailable,
    parse_error, api_failure, no_data, internal_error
};

struct Error {
    ErrorCode     code;
    std::string   message;      // Context-rich, e.g., "Access denied while opening \\.\PhysicalDrive0: run as Administrator."
    std::uint32_t native_code;  // Win32 DWORD or HRESULT
};
```

All Windows resources are wrapped in move-only RAII guards (`FileHandle`, `RegKey`, `DeviceInfoSet`, `ComPtr<T>`, `BCryptAlgorithm`), guaranteeing zero leaks even on early returns or complex control flow.

---

## 📁 Project Structure

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

---

## 🛡️ Security Features

### Anti-Spoofing Detection
- **MAC Address Cross-Validation**: Compares `GetAdaptersAddresses`, WMI, and Registry sources
- **Registry Override Detection**: Detects `NetworkAddress` registry key manipulation
- **Multi-Source Disk Verification**: Cross-checks IOCTL, WMI, and Registry disk information
- **SMBIOS Integrity**: SHA-256 hash of raw SMBIOS tables for tamper detection

### Environment Integrity Checks
- **Code Integrity Status**: KMCI, UMCI, HVCI, test-signing, debug mode flags
- **Secure Boot Verification**: UEFI presence, Secure Boot enabled/disabled, Setup Mode
- **Driver Signature Validation**: Authenticode verification of all loaded kernel drivers
- **BYOVD Detection**: Flags unsigned kernel drivers (Bring Your Own Vulnerable Driver attacks)

### Hardware Swap Detection
- **Historical Registry Tracking**: Monitors `Enum\SCSI`, `Enum\USB`, `Enum\DISPLAY` for past devices
- **PCI Device History**: Tracks all PCI devices ever connected to the system
- **USB Device History**: Maintains records of USB, USBSTOR, and SWD devices

---

## 💡 Use Cases

### 1. Software Licensing
Generate stable hardware fingerprints that survive OS reinstalls but detect hardware changes:
```cpp
auto report = chp3::HwidEngine::collect();
std::string license_key = report->hardware.combined.str();  // Stable across OS reinstalls
```

### 2. Anti-Cheat Systems
Detect environment tampering and spoofer tools:
```cpp
if (report->hardware.mac_spoof_suspected() || 
    report->security.environment_compromised() ||
    report->hardware.unsigned_driver_count() > 50) {
    ban_user("Environment integrity violation");
}
```

### 3. IT Asset Management
Track hardware inventory and detect unauthorized changes:
```cpp
auto gpu_info = chp3::GpuProbe::probe();
auto memory_modules = chp3::MemoryProbe::probe();
auto disks = chp3::DiskRegistryProbe::probe();
// Store in database for inventory tracking
```

---

## 🗺️ Roadmap

- [ ] **VM / Hypervisor Detection**: CPUID hypervisor bits, WMI manufacturer checks, specific VM driver enumeration
- [ ] **Anti-Debug Checks**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (ProcessDebugPort)
- [ ] **Memory Integrity**: Unbacked executable memory scanning (RWX detection), software breakpoint (INT 3) detection
- [ ] **Vcpkg Integration**: Official port recipe for `vcpkg install ctx3-hwid-parser`
- [ ] **Linux Support**: Port core probes to Linux using `/sys`, `/proc`, and `dmidecode`
- [ ] **macOS Support**: Port core probes to macOS using IOKit and system_profiler

---

## 📜 License

This project is licensed under a **Modified MIT License with Attribution and No-Rebranding Restrictions**. See [LICENSE](./LICENSE) for the full text.

**TL;DR:**
- ✅ Free for personal and commercial use
- ✅ Modify the code for your own use
- ❌ Do **not** rebrand, rename, or republish this library as your own
- ❌ Do **not** remove or alter the license, SPDX headers, or version constants
- 📋 If used in an open-source project, include a reference to this repository

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- Uses Windows CNG/BCrypt for SHA-256 hashing
- SMBIOS parsing inspired by dmidecode
- SMART attribute decoding based on smartmontools
- Driver signature verification via WinTrust API

---

## 📞 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

<p align="center">
  <sub>Built with C++20 • Designed for resilience • Powered by cross-validation</sub>
</p>

<p align="center">
  <strong>Version 3.1.0</strong> • Last Updated: May 2026 • CTX3 Development Team
</p>
