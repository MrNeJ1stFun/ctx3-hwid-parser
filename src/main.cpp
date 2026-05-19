// SPDX-License-Identifier: MIT
//===----------------------------------------------------------------------===//
/// @file main.cpp
/// @brief Демонстрационная программа для библиотеки chp3 HWID Parser
/// @details Собирает уникальные идентификаторы оборудования Windows системы
///          и генерирует криптографические хеши для идентификации компьютера
/// @author ItzMrNeJ1stFun
/// @version 3.2.0
/// @date 2024
//===----------------------------------------------------------------------===//

#include "../Include/chp3.hpp"

#include <iostream>
#include <format>
#include <string_view>

namespace {

    /// @brief C++20 совместимый полифилл для std::println (из C++23)
    template<typename... Args>
    void println(std::string_view fmt, Args&&... args) {
        std::cout << std::vformat(fmt, std::make_format_args(args...)) << '\n';
    }

    void println() {
        std::cout << '\n';
    }

    /// @brief Выводит заголовок секции в консоль
    /// @param title Название секции
    void print_section(std::string_view title) {
        println("");
        println("==================================================");
        println("  {}", title);
        println("==================================================");
    }

    /// @brief Выводит опциональное значение или "<unavailable>"
    /// @tparam T Тип значения (должен иметь метод str())
    /// @param label Метка для вывода
    /// @param v Опциональное значение
    template <class T>
    void print_optional(std::string_view label, const std::optional<T>& v) {
        if (v) println("  {:<14}: {}", label, v->str());
        else   println("  {:<14}: <unavailable>", label);
    }

    /// @brief Выводит список некритичных ошибок
    /// @param label Название категории ошибок
    /// @param errs Список ошибок
    void print_errors(std::string_view label, std::span<const chp3::Error> errs) {
        if (errs.empty()) return;
        println("");
        println("  -- {} (non-fatal) --", label);
        for (const auto& e : errs) println("    * {}", e.to_string());
    }

}  // namespace

/// @brief Точка входа в программу
/// @return 0 при успешном выполнении, 1 при критической ошибке
int main() {
    println("chp3 HWID parser v{}", chp3::version_string());

    // ========================================================================
    // ИНДИВИДУАЛЬНЫЕ ПРОБЫ - демонстрация работы каждого зонда отдельно
    // ========================================================================

    print_section("INDIVIDUAL PROBES");

    if (auto r = chp3::CpuProbe::probe(); r)
        println("  CPU            : {}", r->str());
    else
        println("  CPU            : ERR  {}", r.error().to_string());

    if (auto r = chp3::MotherboardProbe::probe(); r)
        println("  Motherboard    : {}", r->str());
    else
        println("  Motherboard    : ERR  {}", r.error().to_string());

    if (auto r = chp3::BiosProbe::probe(); r)
        println("  BIOS           : {}", r->str());
    else
        println("  BIOS           : ERR  {}", r.error().to_string());

    if (auto r = chp3::BaseboardProbe::probe(); r)
        println("  Baseboard      : {}", r->str());
    else
        println("  Baseboard      : ERR  {}", r.error().to_string());

    if (auto r = chp3::SystemUuidProbe::probe(); r)
        println("  System UUID    : {}", r->str());
    else
        println("  System UUID    : ERR  {}", r.error().to_string());

    if (auto r = chp3::ChassisProbe::probe(); r)
        println("  Chassis        : {}", r->to_fingerprint());
    else
        println("  Chassis        : ERR  {}", r.error().to_string());

    if (auto r = chp3::MemoryProbe::probe(); r) {
        println("  Memory modules :");
        for (const auto& m : *r) {
            if (!m.populated()) {
                println("      - [{}] <empty>", m.device_locator);
                continue;
            }
            println("      - [{}] {} MB @ {} MT/s, mfr='{}', part='{}', sn='{}'",
                m.device_locator, m.size_mb, m.speed_mts,
                m.manufacturer, m.part_number, m.serial_number);
        }
    }
    else {
        println("  Memory modules : ERR  {}", r.error().to_string());
    }

    // Method chaining demo: DiskProbe{}.open(0).read_serial()
    if (auto r = chp3::DiskProbe{}.open(0).read_serial(); r)
        println("  Disk #0 serial : {}", r->str());
    else
        println("  Disk #0 serial : ERR  {}", r.error().to_string());

    if (auto r = chp3::NetworkProbe::probe(); r) {
        println("  MAC addresses  :");
        for (const auto& m : *r) println("      - {}", m.str());
    }
    else {
        println("  MAC addresses  : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::GpuProbe::probe(); r)
        println("  GPU            : {}", r->str());
    else
        println("  GPU            : ERR  {}", r.error().to_string());

    if (auto r = chp3::GpuProbe::details(); r) {
        println("  GPU details    :");
        for (const auto& a : *r)
            println("      - {} [{:04X}:{:04X}], VRAM={} MB, LUID={:08X}-{:08X}",
                a.description, a.vendor_id, a.device_id,
                a.dedicated_vram_mb, a.luid_high, a.luid_low);
    }
    else {
        println("  GPU details    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::TpmProbe::probe(); r)
        println("  TPM            : {}", r->to_fingerprint());
    else
        println("  TPM            : ERR  {}", r.error().to_string());

    if (auto r = chp3::MonitorProbe::probe(); r)
        println("  Monitor        : {}", r->str());
    else
        println("  Monitor        : ERR  {}", r.error().to_string());

    if (auto r = chp3::VolumeProbe::probe('C'); r)
        println("  Volume C:\\     : {}", r->str());
    else
        println("  Volume C:\\     : ERR  {}", r.error().to_string());

    if (auto r = chp3::WindowsIdentityProbe::probe(); r) {
        println("  ProductId      : {}", r->product_id);
        println("  Computer name  : {}", r->computer_name);
        println("  User SID       : {}", r->user_sid);
    }
    else {
        println("  Identity       : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::OsInfoProbe::probe(); r)
        println("  OS             : {} {} {} ({}.{}.{}.{}) {}",
            r->product_name, r->edition_id, r->release_id,
            r->major, r->minor, r->build, r->ubr, r->architecture);
    else
        println("  OS             : ERR  {}", r.error().to_string());

    if (auto r = chp3::InstallDateProbe::probe(); r)
        println("  Install date   : {} (epoch={})", r->formatted, r->unix_epoch);
    else
        println("  Install date   : ERR  {}", r.error().to_string());

    if (auto r = chp3::TimeZoneProbe::probe(); r)
        println("  Time zone      : {} ({})", r->key_name.empty() ? r->standard_name : r->key_name,
            r->daylight_active ? "DST active" : "standard");
    else
        println("  Time zone      : ERR  {}", r.error().to_string());

    if (auto r = chp3::KeyboardLayoutProbe::probe(); r)
        println("  Keyboards      : {}", r->to_fingerprint());
    else
        println("  Keyboards      : ERR  {}", r.error().to_string());

    // Поиск NVMe дисков: перебираем PhysicalDrive0..9
    // Необходимо т.к. NVMe может быть на любом индексе
    bool found_nvme = false;
    for (int i = 0; i < 10 && !found_nvme; ++i) {
        if (auto r = chp3::NvmeProbe::probe(i); r) {
            println("  NVMe drive {}   : {}", i, r->to_fingerprint());
            found_nvme = true;
        }
    }
    if (!found_nvme)
        println("  NVMe drive     : <not found or not accessible>");

    if (auto r = chp3::NetworkWmiProbe::probe(); r) {
        println("  WMI MACs       :");
        for (const auto& m : *r) println("      - {}", m.str());
    }
    else {
        println("  WMI MACs       : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::NetworkRegistryProbe::probe(); r) {
        println("  Registry NICs  :");
        for (const auto& a : *r) {
            if (a.is_overridden())
                println("      - [{}] {} (NetworkAddress override = {} <- SUSPICIOUS)",
                    a.subkey, a.driver_desc, a.network_address_override);
            else
                println("      - [{}] {}", a.subkey, a.driver_desc);
        }
    }
    else {
        println("  Registry NICs  : ERR  {}", r.error().to_string());
    }

    print_section("TIER 2 PROBES");

    if (auto r = chp3::HddSmartProbe::probe(0); r) {
        println("  HDD SMART #0   : {}", r->to_summary());
        for (const auto& a : r->attributes)
            println("      - id=0x{:02X} cur={:>3} worst={:>3} raw=0x{:012X}",
                a.id, a.current, a.worst, a.raw);
    }
    else {
        println("  HDD SMART #0   : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::PciDeviceProbe::probe(); r) {
        println("  PCI present    : {} device(s)", r->present.size());
        for (const auto& d : r->present)
            println("      - [{:04X}:{:04X}] sub=[{:04X}:{:04X}] {} ({})",
                d.vendor_id, d.device_id,
                d.subsys_vendor_id, d.subsys_device_id,
                d.description, d.class_name);
        if (const auto hidden = r->historical_only(); !hidden.empty()) {
            println("      hidden (registry-only, {}): ", hidden.size());
            for (const auto& s : hidden) println("        * {}", s);
        }
    }
    else {
        println("  PCI present    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::UsbProbe::probe(); r) {
        println("  USB present    : {} device(s)", r->present.size());
        for (const auto& d : r->present)
            println("      - [{:04X}:{:04X}] {} ({})",
                d.vendor_id, d.product_id, d.description, d.serial_token);
        println("      historical: USB={} USBSTOR={} SWD={}",
            r->registry_keys.size(), r->usbstor_keys.size(), r->swd_keys.size());
    }
    else {
        println("  USB present    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::DiskRegistryProbe::probe(); r) {
        println("  Disk registry  : {} entry(ies)", r->size());
        for (const auto& e : *r)
            println("      - [{}] {} / {}  '{}'",
                e.source, e.device_key, e.instance_key, e.friendly_name);
    }
    else {
        println("  Disk registry  : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::MonitorRegistryProbe::probe(); r) {
        println("  Monitor reg    : {} entry(ies)", r->size());
        for (const auto& e : *r)
            println("      - {} / {}  '{}'",
                e.monitor_id, e.instance_key, e.friendly_name);
    }
    else {
        println("  Monitor reg    : ERR  {}", r.error().to_string());
    }

    if (auto r = chp3::SmbiosWmiProbe::probe(); r)
        println("  SMBIOS (WMI)   : {}", r->to_summary());
    else
        println("  SMBIOS (WMI)   : ERR  {}", r.error().to_string());

    if (auto r = chp3::InstalledDriversProbe::probe(); r) {
        println("  Drivers        : {}", r->to_summary());
        std::size_t bad = 0;
        for (const auto& d : r->drivers) {
            if (d.signature_checked && !d.signature_valid && bad < 8) {
                println("      - UNSIGNED  {}  ({})  status=0x{:08X}",
                    d.base_name, d.full_path,
                    static_cast<std::uint32_t>(d.wintrust_status));
                ++bad;
            }
        }
        if (r->signed_bad > bad)
            println("      ... and {} more unsigned", r->signed_bad - bad);
    }
    else {
        println("  Drivers        : ERR  {}", r.error().to_string());
    }

    print_section("SECURITY PROBES");

    if (auto r = chp3::CodeIntegrityProbe::probe(); r)
        println("  Code integrity : {}", r->to_summary());
    else
        println("  Code integrity : ERR  {}", r.error().to_string());

    if (auto r = chp3::SecureBootProbe::probe(); r)
        println("  Secure Boot    : {}", r->to_summary());
    else
        println("  Secure Boot    : ERR  {}", r.error().to_string());

    // ========================================================================
    // АГРЕГИРОВАННЫЙ ОТЧЁТ - сбор всех данных и генерация HWID хешей
    // ========================================================================

    print_section("AGGREGATED HWID");

    const auto report = chp3::HwidEngine::collect();
    if (!report) {
        println("FATAL: {}", report.error().to_string());
        return 1;
    }
    const auto& rep = *report;

    print_optional("CPU", rep.hardware.cpu);
    print_optional("Motherboard", rep.hardware.motherboard);
    print_optional("Baseboard", rep.hardware.baseboard);
    print_optional("System UUID", rep.hardware.system_uuid);
    print_optional("BIOS", rep.hardware.bios);
    if (rep.hardware.chassis)
        println("  {:<14}: {}", "Chassis", rep.hardware.chassis->to_fingerprint());
    else
        println("  {:<14}: <unavailable>", "Chassis");
    if (rep.hardware.memory.empty()) println("  {:<14}: <unavailable>", "Memory");
    else {
        println("  {:<14}:", "Memory");
        for (const auto& m : rep.hardware.memory) {
            if (!m.populated()) continue;
            println("                  - {}", m.to_fingerprint());
        }
    }
    print_optional("Disk", rep.hardware.disk);
    if (rep.hardware.nvme)
        println("  {:<14}: {}", "NVMe", rep.hardware.nvme->to_fingerprint());
    else
        println("  {:<14}: <unavailable>", "NVMe");
    print_optional("GPU", rep.hardware.gpu);
    print_optional("Monitor", rep.hardware.monitor);
    if (rep.hardware.tpm)
        println("  {:<14}: {}", "TPM", rep.hardware.tpm->to_fingerprint());
    else
        println("  {:<14}: <unavailable>", "TPM");
    if (rep.hardware.macs.empty()) println("  {:<14}: <unavailable>", "MAC");
    else {
        println("  {:<14}:", "MAC");
        for (const auto& m : rep.hardware.macs) println("                  - {}", m.str());
    }
    if (!rep.hardware.macs_wmi.empty()) {
        println("  {:<14}:", "MAC (WMI)");
        for (const auto& m : rep.hardware.macs_wmi) println("                  - {}", m.str());
    }
    if (!rep.hardware.macs_registry.empty()) {
        println("  {:<14}:", "MAC (registry)");
        for (const auto& a : rep.hardware.macs_registry) {
            if (a.is_overridden())
                println("                  - [{}] {}  override={}",
                    a.subkey, a.driver_desc, a.network_address_override);
            else
                println("                  - [{}] {}", a.subkey, a.driver_desc);
        }
    }
    if (rep.hardware.mac_spoof_suspected())
        println("  {:<14}: {}", "!! anti-spoof",
            "MAC sources disagree OR registry override present");
    if (rep.hardware.hdd_smart)
        println("  {:<14}: {}", "HDD SMART", rep.hardware.hdd_smart->to_summary());
    if (rep.hardware.pci)
        println("  {:<14}: {} present, {} hidden",
            "PCI", rep.hardware.pci->present.size(),
            rep.hardware.pci_hidden_count());
    if (rep.hardware.usb)
        println("  {:<14}: {} present, USB-hist={} USBSTOR={} SWD={}",
            "USB", rep.hardware.usb->present.size(),
            rep.hardware.usb->registry_keys.size(),
            rep.hardware.usb->usbstor_keys.size(),
            rep.hardware.usb->swd_keys.size());
    if (!rep.hardware.disk_registry.empty())
        println("  {:<14}: {} entry(ies)",
            "Disk reg", rep.hardware.disk_registry.size());
    if (!rep.hardware.monitor_registry.empty())
        println("  {:<14}: {} entry(ies)",
            "Monitor reg", rep.hardware.monitor_registry.size());
    if (rep.hardware.smbios_wmi)
        println("  {:<14}: {}",
            "SMBIOS (WMI)", rep.hardware.smbios_wmi->to_summary());
    if (rep.hardware.drivers)
        println("  {:<14}: {}",
            "Drivers", rep.hardware.drivers->to_summary());
    if (rep.hardware.unsigned_driver_count() > 0)
        println("  {:<14}: {} unsigned kernel module(s) loaded",
            "!! BYOVD?", rep.hardware.unsigned_driver_count());
    print_optional("Volume", rep.software.volume);
    if (rep.software.identity) {
        println("  {:<14}: {}", "ProductId", rep.software.identity->product_id);
        println("  {:<14}: {}", "Computer name", rep.software.identity->computer_name);
        println("  {:<14}: {}", "User SID", rep.software.identity->user_sid);
    }
    if (rep.software.os)
        println("  {:<14}: {}", "OS", rep.software.os->to_fingerprint());
    if (rep.software.install_date)
        println("  {:<14}: {}", "Install date", rep.software.install_date->formatted);
    if (rep.software.time_zone)
        println("  {:<14}: {}", "Time zone", rep.software.time_zone->to_fingerprint());
    if (rep.software.keyboards)
        println("  {:<14}: {}", "Keyboards", rep.software.keyboards->to_fingerprint());

    println("");
    println("  -- Security --");
    if (rep.security.code_integrity)
        println("  {:<14}: {}", "Code integrity", rep.security.code_integrity->to_summary());
    else
        println("  {:<14}: <unavailable>", "Code integrity");
    if (rep.security.secure_boot)
        println("  {:<14}: {}", "Secure Boot", rep.security.secure_boot->to_summary());
    else
        println("  {:<14}: <unavailable>", "Secure Boot");
    if (rep.security.environment_compromised())
        println("  {:<14}: {}", "!! verdict",
            "environment compromised (testsign / debug / CI off)");

    println("");
    println("  Hardware HWID  : {}", rep.hardware.combined.str());
    println("  Software HWID  : {}", rep.software.combined.str());
    println("  Full      HWID : {}", rep.full.str());

    print_errors("hardware probe issues", rep.hardware.partial_errors);
    print_errors("software probe issues", rep.software.partial_errors);
    print_errors("security probe issues", rep.security.partial_errors);

    println("");
    println("Press Enter to exit...");
    std::cin.get();

    return 0;
}