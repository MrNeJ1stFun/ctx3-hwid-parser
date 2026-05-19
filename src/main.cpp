// SPDX-License-Identifier: MIT
//===----------------------------------------------------------------------===//
/// @file main.cpp
/// @brief Демонстрационная программа для библиотеки chp3 HWID Parser
/// @details Собирает уникальные идентификаторы оборудования Windows системы
///          и генерирует криптографические хеши для идентификации компьютера
/// @author ItzMrNeJ1stFun
/// @version 3.0.0
/// @date 2024
//===----------------------------------------------------------------------===//

#include "../Include/chp3.hpp"

#include <iostream>
#include <print>      // C++23

namespace {

/// @brief Выводит заголовок секции в консоль
/// @param title Название секции
void print_section(std::string_view title) {
    std::println("");
    std::println("==================================================");
    std::println("  {}", title);
    std::println("==================================================");
}

/// @brief Выводит опциональное значение или "<unavailable>"
/// @tparam T Тип значения (должен иметь метод str())
/// @param label Метка для вывода
/// @param v Опциональное значение
template <class T>
void print_optional(std::string_view label, const std::optional<T>& v) {
    if (v) std::println("  {:<14}: {}", label, v->str());
    else   std::println("  {:<14}: <unavailable>", label);
}

/// @brief Выводит список некритичных ошибок
/// @param label Название категории ошибок
/// @param errs Список ошибок
void print_errors(std::string_view label, std::span<const chp3::Error> errs) {
    if (errs.empty()) return;
    std::println("");
    std::println("  -- {} (non-fatal) --", label);
    for (const auto& e : errs) std::println("    * {}", e.to_string());
}

}  // namespace

/// @brief Точка входа в программу
/// @return 0 при успешном выполнении, 1 при критической ошибке
int main() {
    std::println("chp3 HWID parser v{}", chp3::version_string());

    // ========================================================================
    // ИНДИВИДУАЛЬНЫЕ ПРОБЫ - демонстрация работы каждого зонда отдельно
    // ========================================================================

    print_section("INDIVIDUAL PROBES");

    if (auto r = chp3::CpuProbe::probe(); r)
        std::println("  CPU            : {}", r->str());
    else
        std::println("  CPU            : ERR  {}", r.error().to_string());

    if (auto r = chp3::MotherboardProbe::probe(); r)
        std::println("  Motherboard    : {}", r->str());
    else
        std::println("  Motherboard    : ERR  {}", r.error().to_string());

    if (auto r = chp3::BiosProbe::probe(); r)
        std::println("  BIOS           : {}", r->str());
    else
        std::println("  BIOS           : ERR  {}", r.error().to_string());

    if (auto r = chp3::BaseboardProbe::probe(); r)
        std::println("  Baseboard      : {}", r->str());
    else
        std::println("  Baseboard      : ERR  {}", r.error().to_string());

    if (auto r = chp3::SystemUuidProbe::probe(); r)
        std::println("  System UUID    : {}", r->str());
    else
        std::println("  System UUID    : ERR  {}", r.error().to_string());

    if (auto r = chp3::ChassisProbe::probe(); r)
        std::println("  Chassis        : {}", r->to_fingerprint());
    else
        std::println("  Chassis        : ERR  {}", r.error().to_string());

    if (auto r = chp3::MemoryProbe::probe(); r) {
        std::println("  Memory modules :");
        for (const auto& m : *r) {
            if (!m.populated()) {
                std::println("      - [{}] <empty>", m.device_locator);
                continue;
            }
            std::println("      - [{}] {} MB @ {} MT/s, mfr='{}', part='{}', sn='{}'",
                m.device_locator, m.size_mb, m.speed_mts,
                m.manufacturer, m.part_number, m.serial_number);
        }
    } else {
        std::println("  Memory modules : ERR  {}", r.error().to_string());
    }

    // Method chaining demo: DiskProbe{}.open(0).read_serial()
    if (auto r = chp3::DiskProbe{}.open(0).read_serial(); r)
        std::println("  Disk #0 serial : {}", r->str());
    else
        std::println("  Disk #0 serial : ERR  {}", r.error().to_string());

    if (auto r = chp3::NetworkProbe::probe(); r) {
        std::println("  MAC addresses  :");
        for (const auto& m : *r) std::println("      - {}", m.str());
    } else {
        std::println("  MAC addresses  : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::GpuProbe::probe(); r)
        std::println("  GPU            : {}", r->str());
    else
        std::println("  GPU            : ERR  {}", r.error().to_string());

    if (auto r = chp3::GpuProbe::details(); r) {
        std::println("  GPU details    :");
        for (const auto& a : *r)
            std::println("      - {} [{:04X}:{:04X}], VRAM={} MB, LUID={:08X}-{:08X}",
                a.description, a.vendor_id, a.device_id,
                a.dedicated_vram_mb, a.luid_high, a.luid_low);
    } else {
        std::println("  GPU details    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::TpmProbe::probe(); r)
        std::println("  TPM            : {}", r->to_fingerprint());
    else
        std::println("  TPM            : ERR  {}", r.error().to_string());

    if (auto r = chp3::MonitorProbe::probe(); r)
        std::println("  Monitor        : {}", r->str());
    else
        std::println("  Monitor        : ERR  {}", r.error().to_string());

    if (auto r = chp3::VolumeProbe::probe('C'); r)
        std::println("  Volume C:\\     : {}", r->str());
    else
        std::println("  Volume C:\\     : ERR  {}", r.error().to_string());

    if (auto r = chp3::WindowsIdentityProbe::probe(); r) {
        std::println("  ProductId      : {}", r->product_id);
        std::println("  Computer name  : {}", r->computer_name);
        std::println("  User SID       : {}", r->user_sid);
    } else {
        std::println("  Identity       : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::OsInfoProbe::probe(); r)
        std::println("  OS             : {} {} {} ({}.{}.{}.{}) {}",
            r->product_name, r->edition_id, r->release_id,
            r->major, r->minor, r->build, r->ubr, r->architecture);
    else
        std::println("  OS             : ERR  {}", r.error().to_string());

    if (auto r = chp3::InstallDateProbe::probe(); r)
        std::println("  Install date   : {} (epoch={})", r->formatted, r->unix_epoch);
    else
        std::println("  Install date   : ERR  {}", r.error().to_string());

    if (auto r = chp3::TimeZoneProbe::probe(); r)
        std::println("  Time zone      : {} ({})", r->key_name.empty() ? r->standard_name : r->key_name,
            r->daylight_active ? "DST active" : "standard");
    else
        std::println("  Time zone      : ERR  {}", r.error().to_string());

    if (auto r = chp3::KeyboardLayoutProbe::probe(); r)
        std::println("  Keyboards      : {}", r->to_fingerprint());
    else
        std::println("  Keyboards      : ERR  {}", r.error().to_string());

    // Поиск NVMe дисков: перебираем PhysicalDrive0..9
    // Необходимо т.к. NVMe может быть на любом индексе
    bool found_nvme = false;
    for (int i = 0; i < 10 && !found_nvme; ++i) {
        if (auto r = chp3::NvmeProbe::probe(i); r) {
            std::println("  NVMe drive {}   : {}", i, r->to_fingerprint());
            found_nvme = true;
        }
    }
    if (!found_nvme)
        std::println("  NVMe drive     : <not found or not accessible>");

    if (auto r = chp3::NetworkWmiProbe::probe(); r) {
        std::println("  WMI MACs       :");
        for (const auto& m : *r) std::println("      - {}", m.str());
    } else {
        std::println("  WMI MACs       : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::NetworkRegistryProbe::probe(); r) {
        std::println("  Registry NICs  :");
        for (const auto& a : *r) {
            if (a.is_overridden())
                std::println("      - [{}] {} (NetworkAddress override = {} <- SUSPICIOUS)",
                    a.subkey, a.driver_desc, a.network_address_override);
            else
                std::println("      - [{}] {}", a.subkey, a.driver_desc);
        }
    } else {
        std::println("  Registry NICs  : ERR  {}", r.error().to_string());
    }

    print_section("TIER 2 PROBES");

    if (auto r = chp3::HddSmartProbe::probe(0); r) {
        std::println("  HDD SMART #0   : {}", r->to_summary());
        for (const auto& a : r->attributes)
            std::println("      - id=0x{:02X} cur={:>3} worst={:>3} raw=0x{:012X}",
                a.id, a.current, a.worst, a.raw);
    } else {
        std::println("  HDD SMART #0   : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::PciDeviceProbe::probe(); r) {
        std::println("  PCI present    : {} device(s)", r->present.size());
        for (const auto& d : r->present)
            std::println("      - [{:04X}:{:04X}] sub=[{:04X}:{:04X}] {} ({})",
                d.vendor_id, d.device_id,
                d.subsys_vendor_id, d.subsys_device_id,
                d.description, d.class_name);
        if (const auto hidden = r->historical_only(); !hidden.empty()) {
            std::println("      hidden (registry-only, {}): ", hidden.size());
            for (const auto& s : hidden) std::println("        * {}", s);
        }
    } else {
        std::println("  PCI present    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::UsbProbe::probe(); r) {
        std::println("  USB present    : {} device(s)", r->present.size());
        for (const auto& d : r->present)
            std::println("      - [{:04X}:{:04X}] {} ({})",
                d.vendor_id, d.product_id, d.description, d.serial_token);
        std::println("      historical: USB={} USBSTOR={} SWD={}",
            r->registry_keys.size(), r->usbstor_keys.size(), r->swd_keys.size());
    } else {
        std::println("  USB present    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::DiskRegistryProbe::probe(); r) {
        std::println("  Disk registry  : {} entry(ies)", r->size());
        for (const auto& e : *r)
            std::println("      - [{}] {} / {}  '{}'",
                e.source, e.device_key, e.instance_key, e.friendly_name);
    } else {
        std::println("  Disk registry  : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::MonitorRegistryProbe::probe(); r) {
        std::println("  Monitor reg    : {} entry(ies)", r->size());
        for (const auto& e : *r)
            std::println("      - {} / {}  '{}'",
                e.monitor_id, e.instance_key, e.friendly_name);
    } else {
        std::println("  Monitor reg    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::SmbiosWmiProbe::probe(); r)
        std::println("  SMBIOS (WMI)   : {}", r->to_summary());
    else
        std::println("  SMBIOS (WMI)   : ERR  {}", r.error().to_string());

    if (auto r = chp3::InstalledDriversProbe::probe(); r) {
        std::println("  Drivers        : {}", r->to_summary());
        std::size_t bad = 0;
        for (const auto& d : r->drivers) {
            if (d.signature_checked && !d.signature_valid && bad < 8) {
                std::println("      - UNSIGNED  {}  ({})  status=0x{:08X}",
                    d.base_name, d.full_path,
                    static_cast<std::uint32_t>(d.wintrust_status));
                ++bad;
            }
        }
        if (r->signed_bad > bad)
            std::println("      ... and {} more unsigned", r->signed_bad - bad);
    } else {
        std::println("  Drivers        : ERR  {}", r.error().to_string());
    }

    print_section("SECURITY PROBES");

    if (auto r = chp3::CodeIntegrityProbe::probe(); r)
        std::println("  Code integrity : {}", r->to_summary());
    else
        std::println("  Code integrity : ERR  {}", r.error().to_string());

    if (auto r = chp3::SecureBootProbe::probe(); r)
        std::println("  Secure Boot    : {}", r->to_summary());
    else
        std::println("  Secure Boot    : ERR  {}", r.error().to_string());

    // ========================================================================
    // АГРЕГИРОВАННЫЙ ОТЧЁТ - сбор всех данных и генерация HWID хешей
    // ========================================================================

    print_section("AGGREGATED HWID");

    const auto report = chp3::HwidEngine::collect();
    if (!report) {
        std::println("FATAL: {}", report.error().to_string());
        return 1;
    }
    const auto& rep = *report;

    print_optional("CPU",         rep.hardware.cpu);
    print_optional("Motherboard", rep.hardware.motherboard);
    print_optional("Baseboard",   rep.hardware.baseboard);
    print_optional("System UUID", rep.hardware.system_uuid);
    print_optional("BIOS",        rep.hardware.bios);
    if (rep.hardware.chassis)
        std::println("  {:<14}: {}", "Chassis", rep.hardware.chassis->to_fingerprint());
    else
        std::println("  {:<14}: <unavailable>", "Chassis");
    if (rep.hardware.memory.empty()) std::println("  {:<14}: <unavailable>", "Memory");
    else {
        std::println("  {:<14}:", "Memory");
        for (const auto& m : rep.hardware.memory) {
            if (!m.populated()) continue;
            std::println("                  - {}", m.to_fingerprint());
        }
    }
    print_optional("Disk",        rep.hardware.disk);
    if (rep.hardware.nvme)
        std::println("  {:<14}: {}", "NVMe", rep.hardware.nvme->to_fingerprint());
    else
        std::println("  {:<14}: <unavailable>", "NVMe");
    print_optional("GPU",         rep.hardware.gpu);
    print_optional("Monitor",     rep.hardware.monitor);
    if (rep.hardware.tpm)
        std::println("  {:<14}: {}", "TPM", rep.hardware.tpm->to_fingerprint());
    else
        std::println("  {:<14}: <unavailable>", "TPM");
    if (rep.hardware.macs.empty()) std::println("  {:<14}: <unavailable>", "MAC");
    else {
        std::println("  {:<14}:", "MAC");
        for (const auto& m : rep.hardware.macs) std::println("                  - {}", m.str());
    }
    if (!rep.hardware.macs_wmi.empty()) {
        std::println("  {:<14}:", "MAC (WMI)");
        for (const auto& m : rep.hardware.macs_wmi) std::println("                  - {}", m.str());
    }
    if (!rep.hardware.macs_registry.empty()) {
        std::println("  {:<14}:", "MAC (registry)");
        for (const auto& a : rep.hardware.macs_registry) {
            if (a.is_overridden())
                std::println("                  - [{}] {}  override={}",
                    a.subkey, a.driver_desc, a.network_address_override);
            else
                std::println("                  - [{}] {}", a.subkey, a.driver_desc);
        }
    }
    if (rep.hardware.mac_spoof_suspected())
        std::println("  {:<14}: {}", "!! anti-spoof",
            "MAC sources disagree OR registry override present");
    if (rep.hardware.hdd_smart)
        std::println("  {:<14}: {}", "HDD SMART", rep.hardware.hdd_smart->to_summary());
    if (rep.hardware.pci)
        std::println("  {:<14}: {} present, {} hidden",
            "PCI", rep.hardware.pci->present.size(),
            rep.hardware.pci_hidden_count());
    if (rep.hardware.usb)
        std::println("  {:<14}: {} present, USB-hist={} USBSTOR={} SWD={}",
            "USB", rep.hardware.usb->present.size(),
            rep.hardware.usb->registry_keys.size(),
            rep.hardware.usb->usbstor_keys.size(),
            rep.hardware.usb->swd_keys.size());
    if (!rep.hardware.disk_registry.empty())
        std::println("  {:<14}: {} entry(ies)",
            "Disk reg", rep.hardware.disk_registry.size());
    if (!rep.hardware.monitor_registry.empty())
        std::println("  {:<14}: {} entry(ies)",
            "Monitor reg", rep.hardware.monitor_registry.size());
    if (rep.hardware.smbios_wmi)
        std::println("  {:<14}: {}",
            "SMBIOS (WMI)", rep.hardware.smbios_wmi->to_summary());
    if (rep.hardware.drivers)
        std::println("  {:<14}: {}",
            "Drivers", rep.hardware.drivers->to_summary());
    if (rep.hardware.unsigned_driver_count() > 0)
        std::println("  {:<14}: {} unsigned kernel module(s) loaded",
            "!! BYOVD?", rep.hardware.unsigned_driver_count());
    print_optional("Volume",      rep.software.volume);
    if (rep.software.identity) {
        std::println("  {:<14}: {}", "ProductId",     rep.software.identity->product_id);
        std::println("  {:<14}: {}", "Computer name", rep.software.identity->computer_name);
        std::println("  {:<14}: {}", "User SID",      rep.software.identity->user_sid);
    }
    if (rep.software.os)
        std::println("  {:<14}: {}", "OS", rep.software.os->to_fingerprint());
    if (rep.software.install_date)
        std::println("  {:<14}: {}", "Install date", rep.software.install_date->formatted);
    if (rep.software.time_zone)
        std::println("  {:<14}: {}", "Time zone", rep.software.time_zone->to_fingerprint());
    if (rep.software.keyboards)
        std::println("  {:<14}: {}", "Keyboards", rep.software.keyboards->to_fingerprint());

    std::println("");
    std::println("  -- Security --");
    if (rep.security.code_integrity)
        std::println("  {:<14}: {}", "Code integrity", rep.security.code_integrity->to_summary());
    else
        std::println("  {:<14}: <unavailable>", "Code integrity");
    if (rep.security.secure_boot)
        std::println("  {:<14}: {}", "Secure Boot", rep.security.secure_boot->to_summary());
    else
        std::println("  {:<14}: <unavailable>", "Secure Boot");
    if (rep.security.environment_compromised())
        std::println("  {:<14}: {}", "!! verdict",
            "environment compromised (testsign / debug / CI off)");

    std::println("");
    std::println("  Hardware HWID  : {}", rep.hardware.combined.str());
    std::println("  Software HWID  : {}", rep.software.combined.str());
    std::println("  Full      HWID : {}", rep.full.str());

    print_errors("hardware probe issues", rep.hardware.partial_errors);
    print_errors("software probe issues", rep.software.partial_errors);
    print_errors("security probe issues", rep.security.partial_errors);

    std::println("");
    std::println("Press Enter to exit...");
    std::cin.get();

    return 0;
}
//tttre
