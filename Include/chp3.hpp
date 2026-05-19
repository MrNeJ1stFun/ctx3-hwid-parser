// SPDX-License-Identifier: MIT
//===----------------------------------------------------------------------===//
/// @file chp3.hpp
/// @brief CTX3 HWID Parser - header-only библиотека v3.1
/// @details Сбор уникальных идентификаторов оборудования Windows систем
///          с использованием современных C++20 паттернов
/// @author ItzMrNeJ1stFun
/// @version 3.1.0
/// @requires C++20, MSVC/clang-cl, Windows 10+
//===----------------------------------------------------------------------===//
#pragma once
#if (!defined(_MSVC_LANG) && __cplusplus < 202002L) || \
    (defined(_MSVC_LANG)  && _MSVC_LANG  < 202002L)
#  error "chp3.hpp requires C++20 (compile with /std:c++20 or newer)."
#endif

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

// Must be included before Windows.h for GetAdaptersAddresses / AF_UNSPEC
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>

#include <bcrypt.h>
#include <iphlpapi.h>
#include <ipifcons.h>
#include <dxgi.h>
#include <SetupAPI.h>
#include <ntddscsi.h>
#include <winioctl.h>
#include <sddl.h>
#include <Lmcons.h>
#include <intrin.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <tbs.h>
#include <wintrust.h>
#include <Softpub.h>
#include <psapi.h>

// Define interface types if not already defined
#ifndef IF_TYPE_ETHERNET_CSMACD
#define IF_TYPE_ETHERNET_CSMACD 6
#endif
#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <ctime>
#include <variant>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

/// @namespace chp3
/// @brief Публичный API библиотеки CTX3 HWID Parser v3
namespace chp3 {

    inline constexpr std::uint32_t version_major = 3;
    inline constexpr std::uint32_t version_minor = 1;
    inline constexpr std::uint32_t version_patch = 0;
    
    /// @brief Возвращает версию библиотеки
    /// @return Строка формата "major.minor.patch"
    [[nodiscard]] constexpr std::string_view version_string() noexcept { return "3.1.0"; }

    //===----------------------- Error / Result -----------------------------===//

    /// @brief Категории ошибок для всех зондов
    /// @details Используется для классификации ошибок без исключений
    enum class ErrorCode : std::uint32_t {
        ok = 0,                 ///< Успешное выполнение
        access_denied,          ///< Отказано в доступе (нужны права администратора)
        not_supported,          ///< Операция не поддерживается
        device_unavailable,     ///< Устройство недоступно
        parse_error,            ///< Ошибка парсинга данных
        api_failure,            ///< Ошибка Windows API
        no_data,                ///< Данные отсутствуют
        internal_error          ///< Внутренняя ошибка библиотеки
    };

    [[nodiscard]] constexpr std::string_view to_string(ErrorCode c) noexcept {
        switch (c) {
        case ErrorCode::ok:                 return "ok";
        case ErrorCode::access_denied:      return "access_denied";
        case ErrorCode::not_supported:      return "not_supported";
        case ErrorCode::device_unavailable: return "device_unavailable";
        case ErrorCode::parse_error:        return "parse_error";
        case ErrorCode::api_failure:        return "api_failure";
        case ErrorCode::no_data:            return "no_data";
        case ErrorCode::internal_error:     return "internal_error";
        }
        return "unknown";
    }

    struct Error {
        ErrorCode     code{ ErrorCode::internal_error };
        std::string   message;
        std::uint32_t native_code{ 0 };

        [[nodiscard]] std::string to_string() const {
            return std::format("[{}] {} (native=0x{:08X})",
                chp3::to_string(code), message, native_code);
        }
    };

    [[nodiscard]] inline Error make_win32_error(DWORD code, std::string_view doing) {
        switch (code) {
        case ERROR_ACCESS_DENIED:
            return { ErrorCode::access_denied,
                    std::format("Access denied while {}: run as Administrator.", doing), code };
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            return { ErrorCode::device_unavailable,
                    std::format("Device or path not found while {}.", doing), code };
        case ERROR_NOT_SUPPORTED:
        case ERROR_INVALID_FUNCTION:
            return { ErrorCode::not_supported,
                    std::format("Operation not supported while {}.", doing), code };
        default: {
            LPSTR raw = nullptr;
            const DWORD n = ::FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, code, 0, reinterpret_cast<LPSTR>(&raw), 0, nullptr);
            std::string sys = (n && raw) ? std::string(raw, n) : "<no system message>";
            if (raw) ::LocalFree(raw);
            while (!sys.empty() &&
                (sys.back() == '\n' || sys.back() == '\r' || sys.back() == ' '))
                sys.pop_back();
            return { ErrorCode::api_failure,
                    std::format("{} failed: {} (Win32 0x{:08X}).", doing, sys, code), code };
        }
        }
    }

    [[nodiscard]] inline Error make_hresult_error(HRESULT hr, std::string_view doing) {
        return { ErrorCode::api_failure,
                std::format("{} failed (HRESULT 0x{:08X}).", doing,
                            static_cast<std::uint32_t>(hr)),
                static_cast<std::uint32_t>(hr) };
    }

    template <class T>
    class [[nodiscard]] Result {
    public:
        using value_type = T;
        using error_type = Error;

        Result(T v) : payload_(std::in_place_index<0>, std::move(v)) {}
        Result(Error e) : payload_(std::in_place_index<1>, std::move(e)) {}

        [[nodiscard]] bool has_value() const noexcept { return payload_.index() == 0; }
        [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

        [[nodiscard]] const T& value() const& { return std::get<0>(payload_); }
        [[nodiscard]] T& value()& { return std::get<0>(payload_); }
        [[nodiscard]] T&& value()&& { return std::get<0>(std::move(payload_)); }

        [[nodiscard]] const Error& error() const& { return std::get<1>(payload_); }

        [[nodiscard]] const T& operator*()  const& noexcept { return std::get<0>(payload_); }
        [[nodiscard]] T& operator*() & noexcept { return std::get<0>(payload_); }
        [[nodiscard]] const T* operator->() const  noexcept { return std::get_if<0>(&payload_); }
        [[nodiscard]] T* operator->()        noexcept { return std::get_if<0>(&payload_); }

        template <class U>
        [[nodiscard]] T value_or(U&& alt) const& {
            return has_value() ? value() : static_cast<T>(std::forward<U>(alt));
        }

    private:
        std::variant<T, Error> payload_;
    };

    template <class T>
    [[nodiscard]] constexpr Result<T> fail(Error e) noexcept { return Result<T>{std::move(e)}; }

    //===----------------------- Strong types --------------------------------===//

    template <class Tag>
    class StrongString {
    public:
        StrongString() = default;
        explicit StrongString(std::string v) noexcept : value_(std::move(v)) {}
        explicit StrongString(const char* v) : value_(v ? v : "") {} // FIX: Disambiguate string literals
        explicit StrongString(std::string_view v) : value_(v) {}

        [[nodiscard]] const std::string& str()   const noexcept { return value_; }
        [[nodiscard]] std::string_view   view()  const noexcept { return value_; }
        [[nodiscard]] bool               empty() const noexcept { return value_.empty(); }
        [[nodiscard]] std::size_t        size()  const noexcept { return value_.size(); }

        auto operator<=>(const StrongString&) const = default;
    private:
        std::string value_;
    };

    struct serial_number_tag_t {};
    struct hash_digest_tag_t {};
    struct hardware_fingerprint_tag_t {};
    struct mac_address_tag_t {};

    using SerialNumber = StrongString<serial_number_tag_t>;
    using HashDigest = StrongString<hash_digest_tag_t>;
    using HardwareFingerprint = StrongString<hardware_fingerprint_tag_t>;
    using MacAddress = StrongString<mac_address_tag_t>;

    //===----------------------- Hex helpers ---------------------------------===//

    namespace detail {
        inline constexpr std::array<char, 16> hex_lut{
            '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
    }

    [[nodiscard]] inline std::string to_hex(std::span<const std::byte> bytes,
        std::string_view sep = "") {
        std::string out;
        out.reserve(bytes.size() * (2 + sep.size()));
        bool first = true;
        for (auto b : bytes) {
            if (!first && !sep.empty()) out.append(sep);
            const auto v = std::to_integer<std::uint8_t>(b);
            out.push_back(detail::hex_lut[v >> 4]);
            out.push_back(detail::hex_lut[v & 0xF]);
            first = false;
        }
        return out;
    }

    [[nodiscard]] inline std::string to_hex(std::span<const std::uint8_t> bytes,
        std::string_view sep = "") {
        return to_hex(std::as_bytes(std::span{ bytes.data(), bytes.size() }), sep);
    }

    //===----------------------- RAII guards ---------------------------------===//

    class FileHandle {
    public:
        FileHandle() = default;
        explicit FileHandle(HANDLE h) noexcept : h_(h) {}
        ~FileHandle() { reset(); }
        FileHandle(const FileHandle&) = delete;
        FileHandle& operator=(const FileHandle&) = delete;
        FileHandle(FileHandle&& o) noexcept : h_(std::exchange(o.h_, INVALID_HANDLE_VALUE)) {}
        FileHandle& operator=(FileHandle&& o) noexcept {
            reset(); h_ = std::exchange(o.h_, INVALID_HANDLE_VALUE); return *this;
        }
        [[nodiscard]] HANDLE get()   const noexcept { return h_; }
        [[nodiscard]] bool   valid() const noexcept {
            return h_ != INVALID_HANDLE_VALUE && h_ != nullptr;
        }
        void reset() noexcept {
            if (valid()) ::CloseHandle(h_);
            h_ = INVALID_HANDLE_VALUE;
        }
    private:
        HANDLE h_{ INVALID_HANDLE_VALUE };
    };

    class RegKey {
    public:
        RegKey() = default;
        explicit RegKey(HKEY k) noexcept : k_(k) {}
        ~RegKey() { if (k_) ::RegCloseKey(k_); }
        RegKey(const RegKey&) = delete;
        RegKey& operator=(const RegKey&) = delete;
        RegKey(RegKey&& o) noexcept : k_(std::exchange(o.k_, nullptr)) {}
        RegKey& operator=(RegKey&& o) noexcept {
            if (this != &o) { if (k_) ::RegCloseKey(k_); k_ = std::exchange(o.k_, nullptr); }
            return *this;
        }
        [[nodiscard]] HKEY get()   const noexcept { return k_; }
        [[nodiscard]] bool valid() const noexcept { return k_ != nullptr; }
    private:
        HKEY k_{ nullptr };
    };

    class DeviceInfoSet {
    public:
        DeviceInfoSet() = default;
        explicit DeviceInfoSet(HDEVINFO h) noexcept : h_(h) {}
        ~DeviceInfoSet() { if (valid()) ::SetupDiDestroyDeviceInfoList(h_); }
        DeviceInfoSet(const DeviceInfoSet&) = delete;
        DeviceInfoSet& operator=(const DeviceInfoSet&) = delete;
        DeviceInfoSet(DeviceInfoSet&& o) noexcept : h_(std::exchange(o.h_, INVALID_HANDLE_VALUE)) {}
        DeviceInfoSet& operator=(DeviceInfoSet&& o) noexcept {
            if (this != &o) { if (valid()) ::SetupDiDestroyDeviceInfoList(h_); h_ = std::exchange(o.h_, INVALID_HANDLE_VALUE); }
            return *this;
        }
        [[nodiscard]] HDEVINFO get()   const noexcept { return h_; }
        [[nodiscard]] bool     valid() const noexcept { return h_ != INVALID_HANDLE_VALUE; }
    private:
        HDEVINFO h_{ INVALID_HANDLE_VALUE };
    };

    class BCryptAlgorithm {
    public:
        explicit BCryptAlgorithm(LPCWSTR algo) noexcept {
            status_ = ::BCryptOpenAlgorithmProvider(&handle_, algo, nullptr, 0);
        }
        ~BCryptAlgorithm() { if (handle_) ::BCryptCloseAlgorithmProvider(handle_, 0); }
        BCryptAlgorithm(const BCryptAlgorithm&) = delete;
        BCryptAlgorithm& operator=(const BCryptAlgorithm&) = delete;
        [[nodiscard]] BCRYPT_ALG_HANDLE get()    const noexcept { return handle_; }
        [[nodiscard]] bool              ok()     const noexcept { return BCRYPT_SUCCESS(status_); }
        [[nodiscard]] NTSTATUS          status() const noexcept { return status_; }
    private:
        BCRYPT_ALG_HANDLE handle_{ nullptr };
        NTSTATUS          status_{ 0 };
    };

    struct ComDeleter { void operator()(IUnknown* p) const noexcept { if (p) p->Release(); } };
    template <class T> using ComPtr = std::unique_ptr<T, ComDeleter>;

    //===----------------------- SHA-256 (BCrypt) ----------------------------===//

    class Sha256 {
    public:
        [[nodiscard]] static Result<HashDigest>
            hash(std::span<const std::byte> data) noexcept {
            BCryptAlgorithm alg{ BCRYPT_SHA256_ALGORITHM };
            if (!alg.ok())
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptOpenAlgorithmProvider(SHA256) failed.",
                    static_cast<std::uint32_t>(alg.status()) });

            DWORD object_size = 0, hash_size = 0, returned = 0;
            if (auto s = ::BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0);
                !BCRYPT_SUCCESS(s))
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptGetProperty(OBJECT_LENGTH) failed.", static_cast<std::uint32_t>(s) });

            if (auto s = ::BCryptGetProperty(alg.get(), BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &returned, 0);
                !BCRYPT_SUCCESS(s))
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptGetProperty(HASH_LENGTH) failed.", static_cast<std::uint32_t>(s) });

            std::vector<std::uint8_t> object(object_size);
            std::vector<std::uint8_t> digest(hash_size);

            BCRYPT_HASH_HANDLE handle{};
            if (auto s = ::BCryptCreateHash(alg.get(), &handle,
                object.data(), object_size, nullptr, 0, 0);
                !BCRYPT_SUCCESS(s))
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptCreateHash failed.", static_cast<std::uint32_t>(s) });

            struct G { BCRYPT_HASH_HANDLE h; ~G() { if (h) ::BCryptDestroyHash(h); } } g{ handle };

            if (auto s = ::BCryptHashData(handle,
                const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())),
                static_cast<ULONG>(data.size()), 0);
                !BCRYPT_SUCCESS(s))
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptHashData failed.", static_cast<std::uint32_t>(s) });

            if (auto s = ::BCryptFinishHash(handle, digest.data(),
                static_cast<ULONG>(digest.size()), 0);
                !BCRYPT_SUCCESS(s))
                return fail<HashDigest>({ ErrorCode::api_failure,
                    "BCryptFinishHash failed.", static_cast<std::uint32_t>(s) });

            return HashDigest{ to_hex(std::span<const std::uint8_t>{digest}) };
        }

        [[nodiscard]] static Result<HashDigest> hash(std::string_view sv) noexcept {
            return hash(std::as_bytes(std::span{ sv.data(), sv.size() }));
        }
    };

    //===----------------------- Probe concept -------------------------------===//

    template <class P>
    concept Probe = requires {
        typename P::output_type;
        { P::probe() } -> std::same_as<Result<typename P::output_type>>;
    };

    //===----------------------- CPU probe -----------------------------------===//

    class CpuProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            std::array<int, 4> regs{};
            ::__cpuid(regs.data(), 0x80000000);
            if (static_cast<std::uint32_t>(regs[0]) < 0x80000004u)
                return fail<HardwareFingerprint>({ ErrorCode::not_supported,
                    "CPU does not expose CPUID brand string.", 0 });

            std::array<char, 49> brand{};
            for (int leaf = 0; leaf < 3; ++leaf) {
                ::__cpuid(regs.data(), 0x80000002 + leaf);
                std::memcpy(brand.data() + leaf * 16, regs.data(), 16);
            }
            std::string brand_str(brand.data());
            while (!brand_str.empty() &&
                (brand_str.back() == '\0' || brand_str.back() == ' '))
                brand_str.pop_back();

            ::__cpuid(regs.data(), 1);
            const auto sig = static_cast<std::uint32_t>(regs[0]);
            const auto features = static_cast<std::uint32_t>(regs[3]);
            const auto family = ((sig >> 8) & 0xF) + ((sig >> 20) & 0xFF);
            const auto model = ((sig >> 4) & 0xF) | ((sig >> 12) & 0xF0);
            const auto stepping = sig & 0xF;
            ::__cpuidex(regs.data(), 7, 0);
            const auto ext = static_cast<std::uint32_t>(regs[1]);

            return HardwareFingerprint{ std::format(
                "{}|FMS={:X}.{:X}.{:X}|sig={:08X}|feat={:08X}|ext={:08X}",
                brand_str, family, model, stepping, sig, features, ext) };
        }
    };

    //===----------------------- SMBIOS table iterator -----------------------===//
	// wtf 
    namespace detail {

        struct SmbiosEntry {
            std::uint8_t  type{ 0 };
            std::uint8_t  length{ 0 };
            std::uint16_t handle{ 0 };
            std::span<const std::uint8_t> formatted;
            std::span<const std::uint8_t> raw;
            std::vector<std::string>      strings;

            [[nodiscard]] std::string pick_string(std::uint8_t idx) const {
                if (idx == 0 || idx > strings.size()) return {};
                return strings[idx - 1];
            }
        };

        class SmbiosTable {
        public:
            [[nodiscard]] static Result<SmbiosTable> load() noexcept {
                constexpr DWORD kRSMB = 'RSMB';
                const DWORD size = ::GetSystemFirmwareTable(kRSMB, 0, nullptr, 0);
                if (size == 0)
                    return fail<SmbiosTable>(make_win32_error(::GetLastError(),
                        "querying SMBIOS firmware table size"));
                std::vector<std::uint8_t> raw(size);
                if (::GetSystemFirmwareTable(kRSMB, 0, raw.data(), size) == 0)
                    return fail<SmbiosTable>(make_win32_error(::GetLastError(),
                        "reading SMBIOS firmware table"));
                if (raw.size() <= 8)
                    return fail<SmbiosTable>({ ErrorCode::parse_error,
                        "SMBIOS table too small.", 0 });
                return SmbiosTable{ std::move(raw) };
            }

            template <class Fn>
            void for_each(Fn&& fn) const {
                std::span<const std::uint8_t> body{ raw_.data() + 8, raw_.size() - 8 };
                std::size_t off = 0;
                while (off + 4 <= body.size()) {
                    const std::uint8_t type = body[off];
                    const std::uint8_t len = body[off + 1];
                    if (len < 4 || off + len > body.size()) break;

                    std::size_t s = off + len;
                    const std::size_t strings_start = s;
                    while (s + 1 < body.size() && !(body[s] == 0 && body[s + 1] == 0)) ++s;
                    const std::size_t entry_end = (s + 2 <= body.size()) ? s + 2 : body.size();

                    SmbiosEntry e;
                    e.type = type;
                    e.length = len;
                    e.handle = static_cast<std::uint16_t>(body[off + 2]) |
                        (static_cast<std::uint16_t>(body[off + 3]) << 8);
                    e.formatted = body.subspan(off + 4, len - 4);
                    e.raw = body.subspan(off, len);
                    e.strings = decode_strings(
                        body.subspan(strings_start, entry_end - strings_start));
                    fn(e);

                    if (type == 127) break;
                    off = entry_end;
                }
            }

        private:
            explicit SmbiosTable(std::vector<std::uint8_t> r) noexcept
                : raw_(std::move(r)) {
            }

            [[nodiscard]] static std::vector<std::string>
                decode_strings(std::span<const std::uint8_t> region) {
                std::vector<std::string> out;
                std::size_t i = 0;
                while (i < region.size() && region[i] != 0) {
                    std::string cur;
                    while (i < region.size() && region[i] != 0) {
                        cur.push_back(static_cast<char>(region[i]));
                        ++i;
                    }
                    out.push_back(std::move(cur));
                    if (i < region.size()) ++i;
                }
                return out;
            }

            std::vector<std::uint8_t> raw_;
        };

    }  // namespace detail

    //===----------------------- Motherboard probe (SMBIOS) ------------------===//

    class MotherboardProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<HardwareFingerprint>(table.error());

            std::string mfr, prod, ser;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (!mfr.empty() || e.type != 1 || e.formatted.size() < 4) return;
                mfr = e.pick_string(e.formatted[0]);
                prod = e.pick_string(e.formatted[1]);
                ser = e.pick_string(e.formatted[3]);
                });

            if (mfr.empty() && prod.empty() && ser.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "SMBIOS Type-1 System Information record not found.", 0 });
            return HardwareFingerprint{ std::format("{}|{}|{}", mfr, prod, ser) };
        }
    };

    //===----------------------- Disk probe (IOCTL) --------------------------===//

    class DiskProbe {
    public:
        using output_type = SerialNumber;

        DiskProbe() = default;

        DiskProbe& open(std::uint32_t physical_index = 0) & noexcept {
            const std::string path = std::format(R"(\\.\PhysicalDrive{})", physical_index);
            FileHandle h{ ::CreateFileA(path.c_str(), 0,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING, 0, nullptr) };
            if (!h.valid()) {
                last_error_ = make_win32_error(::GetLastError(),
                    std::format("opening {}", path));
            }
            else {
                drive_ = std::move(h);
                last_error_.reset();
            }
            return *this;
        }

        [[nodiscard]] DiskProbe&& open(std::uint32_t i = 0) && noexcept {
            open(i); return std::move(*this);
        }

        [[nodiscard]] bool                          is_open()    const noexcept { return drive_.valid(); }
        [[nodiscard]] const std::optional<Error>& last_error() const noexcept { return last_error_; }

        [[nodiscard]] Result<SerialNumber> read_serial() const noexcept {
            if (!is_open())
                return fail<SerialNumber>(last_error_.value_or(Error{
                    ErrorCode::device_unavailable,
                    "DiskProbe::read_serial called without open().", 0 }));

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            std::array<std::uint8_t, 1024> buf{};
            DWORD returned = 0;
            if (!::DeviceIoControl(drive_.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                &query, sizeof(query),
                buf.data(), static_cast<DWORD>(buf.size()),
                &returned, nullptr)) {
                return fail<SerialNumber>(make_win32_error(::GetLastError(),
                    "IOCTL_STORAGE_QUERY_PROPERTY"));
            }

            const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
            auto extract = [&](std::uint32_t off) -> std::string {
                if (!off || off >= buf.size()) return {};
                return std::string{ reinterpret_cast<const char*>(buf.data() + off) };
                };
            auto trim = [](std::string& s) {
                while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
                while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
                };

            std::string product = extract(desc->ProductIdOffset);
            std::string serial = extract(desc->SerialNumberOffset);
            trim(product); trim(serial);

            if (serial.empty())
                return fail<SerialNumber>({ ErrorCode::no_data,
                    "Drive descriptor returned an empty serial number.", 0 });
            return SerialNumber{ product.empty() ? serial : product + "-" + serial };
        }

        [[nodiscard]] static Result<SerialNumber>
            probe(std::uint32_t physical_index = 0) noexcept {
            return DiskProbe{}.open(physical_index).read_serial();
        }

    private:
        FileHandle           drive_;
        std::optional<Error> last_error_;
    };

    static_assert(Probe<DiskProbe>);

    //===----------------------- Network probe (MAC) -------------------------===//

    class NetworkProbe {
    public:
        using output_type = std::vector<MacAddress>;

        [[nodiscard]] static Result<std::vector<MacAddress>> probe() noexcept {
            ULONG size = 0;
            const ULONG flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
            if (::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
                return fail<std::vector<MacAddress>>(
                    make_win32_error(::GetLastError(), "GetAdaptersAddresses (sizing)"));

            std::vector<std::uint8_t> buf(size);
            auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
            if (auto r = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size); r != ERROR_SUCCESS)
                return fail<std::vector<MacAddress>>(make_win32_error(r, "GetAdaptersAddresses"));

            std::vector<MacAddress> out;
            for (auto* p = addrs; p; p = p->Next) {
                if (p->PhysicalAddressLength == 0) continue;
                if (p->IfType != IF_TYPE_ETHERNET_CSMACD && p->IfType != IF_TYPE_IEEE80211) continue;
                out.emplace_back(to_hex(std::span<const std::uint8_t>{p->PhysicalAddress, p->PhysicalAddressLength}, "-"));
            }
            if (out.empty())
                return fail<std::vector<MacAddress>>({ ErrorCode::no_data,
                    "No physical Ethernet/Wi-Fi adapters found.", 0 });
            return out;
        }
    };

    //===----------------------- GPU probe (DXGI) ----------------------------===//

    class GpuProbe {
    public:
        using output_type = HardwareFingerprint;

        struct Adapter {
            std::string   description;
            std::uint32_t vendor_id{ 0 };
            std::uint32_t device_id{ 0 };
            std::uint32_t subsys_id{ 0 };
            std::uint64_t dedicated_vram_mb{ 0 };
            std::int32_t  luid_high{ 0 };
            std::uint32_t luid_low{ 0 };
        };

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            IDXGIFactory1* raw = nullptr;
            if (HRESULT hr = ::CreateDXGIFactory1(__uuidof(IDXGIFactory1),
                reinterpret_cast<void**>(&raw));
                FAILED(hr))
                return fail<HardwareFingerprint>(make_hresult_error(hr, "CreateDXGIFactory1"));

            ComPtr<IDXGIFactory1> factory{ raw };
            std::string acc;
            UINT idx = 0;
            IDXGIAdapter1* a = nullptr;
            while (factory->EnumAdapters1(idx, &a) != DXGI_ERROR_NOT_FOUND) {
                ComPtr<IDXGIAdapter1> adapter{ a };
                DXGI_ADAPTER_DESC1 desc{};
                if (SUCCEEDED(adapter->GetDesc1(&desc)) &&
                    (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0) {
                    if (!acc.empty()) acc += ';';
                    acc += std::format("{:04X}:{:04X}:{:08X}",
                        desc.VendorId, desc.DeviceId, desc.SubSysId);
                }
                ++idx;
            }
            if (acc.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "No physical GPU adapters reported by DXGI.", 0 });
            return HardwareFingerprint{ std::move(acc) };
        }

        [[nodiscard]] static Result<std::vector<Adapter>> details() noexcept {
            IDXGIFactory1* raw = nullptr;
            if (HRESULT hr = ::CreateDXGIFactory1(__uuidof(IDXGIFactory1),
                reinterpret_cast<void**>(&raw));
                FAILED(hr))
                return fail<std::vector<Adapter>>(make_hresult_error(hr, "CreateDXGIFactory1"));

            ComPtr<IDXGIFactory1> factory{ raw };
            std::vector<Adapter> out;
            UINT idx = 0;
            IDXGIAdapter1* a = nullptr;
            while (factory->EnumAdapters1(idx, &a) != DXGI_ERROR_NOT_FOUND) {
                ComPtr<IDXGIAdapter1> adapter{ a };
                DXGI_ADAPTER_DESC1 desc{};
                if (SUCCEEDED(adapter->GetDesc1(&desc))) {
                    Adapter info;
                    std::array<char, 256> name{};
                    std::size_t conv = 0;
                    ::wcstombs_s(&conv, name.data(), name.size(),
                        desc.Description, _TRUNCATE);
                    info.description = std::string{ name.data() };
                    info.vendor_id = desc.VendorId;
                    info.device_id = desc.DeviceId;
                    info.subsys_id = desc.SubSysId;
                    info.dedicated_vram_mb = static_cast<std::uint64_t>(
                        desc.DedicatedVideoMemory) / (1024u * 1024u);
                    info.luid_high = desc.AdapterLuid.HighPart;
                    info.luid_low = desc.AdapterLuid.LowPart;
                    out.push_back(std::move(info));
                }
                ++idx;
            }
            if (out.empty())
                return fail<std::vector<Adapter>>({ ErrorCode::no_data,
                    "No DXGI adapters returned details.", 0 });
            return out;
        }
    };

    //===----------------------- Monitor probe (EDID) ------------------------===//

    class MonitorProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            static constexpr GUID kMonitorClass{
                0x4d36e96e, 0xe325, 0x11ce,
                {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18} };

            DeviceInfoSet set{ ::SetupDiGetClassDevs(&kMonitorClass, nullptr, nullptr, DIGCF_PRESENT) };
            if (!set.valid())
                return fail<HardwareFingerprint>(make_win32_error(::GetLastError(),
                    "SetupDiGetClassDevs(monitor)"));

            std::string acc;
            SP_DEVINFO_DATA dev{};
            dev.cbSize = sizeof(dev);
            for (DWORD i = 0; ::SetupDiEnumDeviceInfo(set.get(), i, &dev); ++i) {
                HKEY raw_key = ::SetupDiOpenDevRegKey(set.get(), &dev,
                    DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                if (raw_key == INVALID_HANDLE_VALUE) continue;
                RegKey key{ raw_key };

                std::array<std::uint8_t, 256> edid{};
                DWORD size = static_cast<DWORD>(edid.size()), type = 0;
                if (::RegQueryValueExA(key.get(), "EDID", nullptr, &type,
                    edid.data(), &size) != ERROR_SUCCESS)
                    continue;
                if (size < 18) continue;

                char pnp[4]{};
                pnp[0] = static_cast<char>('A' + ((edid[8] >> 2) & 0x1F) - 1);
                pnp[1] = static_cast<char>('A' + (((edid[8] & 0x03) << 3)
                    | ((edid[9] >> 5) & 0x07)) - 1);
                pnp[2] = static_cast<char>('A' + (edid[9] & 0x1F) - 1);

                const std::uint16_t prod_id =
                    static_cast<std::uint16_t>(edid[10]) |
                    (static_cast<std::uint16_t>(edid[11]) << 8);
                const std::uint32_t serial =
                    static_cast<std::uint32_t>(edid[12]) |
                    (static_cast<std::uint32_t>(edid[13]) << 8) |
                    (static_cast<std::uint32_t>(edid[14]) << 16) |
                    (static_cast<std::uint32_t>(edid[15]) << 24);

                if (!acc.empty()) acc += ';';
                acc += std::format("{}-{:04X}-{:08X}", pnp, prod_id, serial);
            }
            if (acc.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "No accessible monitor EDID data.", 0 });
            return HardwareFingerprint{ std::move(acc) };
        }
    };

    //===----------------------- Volume probe --------------------------------===//

    class VolumeProbe {
    public:
        using output_type = SerialNumber;

        [[nodiscard]] static Result<SerialNumber> probe(char drive_letter = 'C') noexcept {
            const std::string root = std::format("{}:\\", drive_letter);
            DWORD serial = 0;
            if (!::GetVolumeInformationA(root.c_str(), nullptr, 0, &serial,
                nullptr, nullptr, nullptr, 0))
                return fail<SerialNumber>(make_win32_error(::GetLastError(),
                    std::format("GetVolumeInformation({})", root)));
            return SerialNumber{ std::format("{:08X}", serial) };
        }
    };

    //===----------------------- Windows identity probe ----------------------===//

    class WindowsIdentityProbe {
    public:
        struct Identity {
            std::string product_id;
            std::string computer_name;
            std::string user_sid;
        };
        using output_type = Identity;

        [[nodiscard]] static Result<Identity> probe() noexcept {
            Identity id{
                .product_id = read_product_id(),
                .computer_name = read_computer_name(),
                .user_sid = read_user_sid() };

            if (id.product_id.empty() && id.computer_name.empty() && id.user_sid.empty())
                return fail<Identity>({ ErrorCode::no_data,
                    "Could not read any software identity values.", 0 });
            return id;
        }

    private:
        [[nodiscard]] static std::string read_product_id() noexcept {
            HKEY raw{};
            if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)",
                0, KEY_READ, &raw) != ERROR_SUCCESS) return {};
            RegKey k{ raw };
            std::array<char, 128> buf{};
            DWORD size = static_cast<DWORD>(buf.size()), type = 0;
            if (::RegQueryValueExA(k.get(), "ProductId", nullptr, &type,
                reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS)
                return {};
            return std::string{ buf.data() };
        }

        [[nodiscard]] static std::string read_computer_name() noexcept {
            std::array<char, MAX_COMPUTERNAME_LENGTH + 1> buf{};
            DWORD size = static_cast<DWORD>(buf.size());
            if (!::GetComputerNameA(buf.data(), &size)) return {};
            return std::string{ buf.data() };
        }

        [[nodiscard]] static std::string read_user_sid() noexcept {
            std::array<char, UNLEN + 1> user{};
            DWORD ulen = static_cast<DWORD>(user.size());
            if (!::GetUserNameA(user.data(), &ulen)) return {};

            DWORD sid_size = 0, dom_size = 0;
            SID_NAME_USE use{};
            ::LookupAccountNameA(nullptr, user.data(), nullptr, &sid_size,
                nullptr, &dom_size, &use);
            if (sid_size == 0) return {};

            std::vector<std::uint8_t> sid(sid_size);
            std::vector<char>          dom(dom_size);
            if (!::LookupAccountNameA(nullptr, user.data(),
                sid.data(), &sid_size,
                dom.data(), &dom_size, &use)) return {};

            LPSTR str = nullptr;
            if (!::ConvertSidToStringSidA(sid.data(), &str)) return {};
            std::string out{ str };
            ::LocalFree(str);
            return out;
        }
    };

    //===----------------------- BIOS probe (SMBIOS Type 0) ------------------===//

    class BiosProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<HardwareFingerprint>(table.error());

            std::string vendor, version, release_date;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (!vendor.empty() || e.type != 0 || e.formatted.size() < 5) return;
                vendor = e.pick_string(e.formatted[0]);
                version = e.pick_string(e.formatted[1]);
                release_date = e.pick_string(e.formatted[4]);
                });

            if (vendor.empty() && version.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "SMBIOS Type-0 BIOS Information record not found.", 0 });
            return HardwareFingerprint{ std::format("{}|{}|{}", vendor, version, release_date) };
        }
    };

    //===----------------------- TPM probe (TBS) -----------------------------===//

    class TpmProbe {
    public:
        struct Info {
            std::uint32_t struct_version{ 0 };
            std::uint32_t tpm_version{ 0 };
            std::uint32_t interface_type{ 0 };
            std::uint32_t impl_revision{ 0 };

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("v{}|if={}|rev={:08X}|sv={}",
                    tpm_version, interface_type, impl_revision, struct_version);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            TPM_DEVICE_INFO dev{};
            if (TBS_RESULT r = ::Tbsi_GetDeviceInfo(sizeof(dev), &dev); r != TBS_SUCCESS) {
                return fail<Info>({ ErrorCode::device_unavailable,
                    std::format("TPM not accessible (TBS 0x{:08X}): the TPM may be absent, "
                                "disabled in firmware, or the TPM Base Services service is stopped.",
                                static_cast<std::uint32_t>(r)),
                    static_cast<std::uint32_t>(r) });
            }
            return Info{
                .struct_version = dev.structVersion,
                .tpm_version = dev.tpmVersion,
                .interface_type = dev.tpmInterfaceType,
                .impl_revision = dev.tpmImpRevision };
        }
    };

    //===----------------------- WMI session helper --------------------------===//

    namespace detail {

        inline bool ensure_com_initialized() noexcept {
            static std::atomic<bool> initialized{ false };
            if (initialized.load(std::memory_order_acquire)) return true;
            HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(hr)) {
                initialized.store(true, std::memory_order_release);
                return true;
            }
            return (hr == RPC_E_CHANGED_MODE);
        }

        class WmiSession {
        public:
            explicit WmiSession(const wchar_t* ns = L"ROOT\\CIMV2") noexcept {
                if (!ensure_com_initialized()) { hr_ = CO_E_NOTINITIALIZED; return; }

                IWbemLocator* raw_loc = nullptr;
                if (HRESULT h = ::CoCreateInstance(CLSID_WbemLocator, nullptr,
                    CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                    reinterpret_cast<void**>(&raw_loc));
                    FAILED(h)) {
                    hr_ = h; return;
                }
                loc_.reset(raw_loc);

                IWbemServices* raw_svc = nullptr;
                if (HRESULT h = loc_->ConnectServer(_bstr_t(ns),
                    nullptr, nullptr, nullptr, 0, nullptr, nullptr, &raw_svc);
                    FAILED(h)) {
                    hr_ = h; return;
                }
                svc_.reset(raw_svc);

                if (HRESULT h = ::CoSetProxyBlanket(svc_.get(),
                    RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                    RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                    nullptr, EOAC_NONE);
                    FAILED(h)) {
                    hr_ = h; return;
                }
                ok_ = true;
            }
            ~WmiSession() = default;

            WmiSession(const WmiSession&) = delete;
            WmiSession& operator=(const WmiSession&) = delete;

            [[nodiscard]] bool    ok() const noexcept { return ok_; }
            [[nodiscard]] HRESULT hr() const noexcept { return hr_; }

            template <class Fn>
            [[nodiscard]] HRESULT enumerate(const wchar_t* wql, Fn&& fn) noexcept {
                IEnumWbemClassObject* raw_enum = nullptr;
                if (HRESULT h = svc_->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    nullptr, &raw_enum); FAILED(h))
                    return h;
                ComPtr<IEnumWbemClassObject> en{ raw_enum };

                IWbemClassObject* obj = nullptr;
                ULONG returned = 0;
                while (en->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK && returned > 0) {
                    ComPtr<IWbemClassObject> guard{ obj };
                    fn(*obj);
                    obj = nullptr;
                }
                return S_OK;
            }

        private:
            bool                  ok_{ false };
            HRESULT               hr_{ S_OK };
            ComPtr<IWbemLocator>  loc_;
            ComPtr<IWbemServices> svc_;
        };

        [[nodiscard]] inline std::string get_wmi_string(IWbemClassObject& obj, const wchar_t* prop) {
            VARIANT v;
            ::VariantInit(&v);
            std::string out;
            if (SUCCEEDED(obj.Get(prop, 0, &v, nullptr, nullptr))) {
                if (v.vt == VT_BSTR && v.bstrVal) {
                    const int n = ::WideCharToMultiByte(CP_UTF8, 0, v.bstrVal, -1,
                        nullptr, 0, nullptr, nullptr);
                    if (n > 1) {
                        out.assign(static_cast<std::size_t>(n - 1), '\0');
                        ::WideCharToMultiByte(CP_UTF8, 0, v.bstrVal, -1,
                            out.data(), n, nullptr, nullptr);
                    }
                }
            }
            ::VariantClear(&v);
            return out;
        }

    }  // namespace detail

    //===----------------------- Motherboard via WMI fallback ----------------===//

    class MotherboardWmiProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            detail::WmiSession ses;
            if (!ses.ok())
                return fail<HardwareFingerprint>(make_hresult_error(ses.hr(),
                    "initializing WMI for Win32_BaseBoard"));

            std::string mfr, prod, ser;
            if (HRESULT h = ses.enumerate(
                L"SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard",
                [&](IWbemClassObject& obj) {
                    if (mfr.empty())  mfr = detail::get_wmi_string(obj, L"Manufacturer");
                    if (prod.empty()) prod = detail::get_wmi_string(obj, L"Product");
                    if (ser.empty())  ser = detail::get_wmi_string(obj, L"SerialNumber");
                });
                FAILED(h))
                return fail<HardwareFingerprint>(make_hresult_error(h,
                    "ExecQuery(Win32_BaseBoard)"));

            if (mfr.empty() && prod.empty() && ser.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "Win32_BaseBoard returned no usable rows.", 0 });
            return HardwareFingerprint{ std::format("{}|{}|{}", mfr, prod, ser) };
        }
    };

    //===----------------------- Disk via WMI fallback -----------------------===//

    class DiskWmiProbe {
    public:
        using output_type = SerialNumber;

        [[nodiscard]] static Result<SerialNumber> probe() noexcept {
            detail::WmiSession ses;
            if (!ses.ok())
                return fail<SerialNumber>(make_hresult_error(ses.hr(),
                    "initializing WMI for Win32_DiskDrive"));

            std::string model, serial;
            if (HRESULT h = ses.enumerate(
                L"SELECT Model, SerialNumber FROM Win32_DiskDrive WHERE Index = 0",
                [&](IWbemClassObject& obj) {
                    if (model.empty())  model = detail::get_wmi_string(obj, L"Model");
                    if (serial.empty()) serial = detail::get_wmi_string(obj, L"SerialNumber");
                });
                FAILED(h))
                return fail<SerialNumber>(make_hresult_error(h,
                    "ExecQuery(Win32_DiskDrive)"));

            if (serial.empty())
                return fail<SerialNumber>({ ErrorCode::no_data,
                    "Win32_DiskDrive did not return a serial number.", 0 });
            return SerialNumber{ model.empty() ? serial : model + "-" + serial };
        }
    };

    //===----------------------- OS info probe -------------------------------===//

    class OsInfoProbe {
    public:
        struct Info {
            std::uint32_t major{ 0 };
            std::uint32_t minor{ 0 };
            std::uint32_t build{ 0 };
            std::uint32_t ubr{ 0 };
            std::string   product_name;
            std::string   edition_id;
            std::string   release_id;
            std::string   architecture;

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("{} {}|{}|{}.{}.{}.{}|{}",
                    product_name, edition_id, release_id,
                    major, minor, build, ubr, architecture);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            Info info;

            using rtl_get_version_t = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
            if (HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll"); ntdll) {
                if (auto* fn = reinterpret_cast<rtl_get_version_t>(
                    ::GetProcAddress(ntdll, "RtlGetVersion"))) {
                    RTL_OSVERSIONINFOW osvi{};
                    osvi.dwOSVersionInfoSize = sizeof(osvi);
                    if (fn(&osvi) == 0) {
                        info.major = osvi.dwMajorVersion;
                        info.minor = osvi.dwMinorVersion;
                        info.build = osvi.dwBuildNumber;
                    }
                }
            }

            HKEY raw{};
            if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)",
                0, KEY_READ, &raw) == ERROR_SUCCESS) {
                RegKey k{ raw };
                info.product_name = read_str(k.get(), "ProductName");
                info.edition_id = read_str(k.get(), "EditionID");
                info.release_id = read_str(k.get(), "DisplayVersion");
                if (info.release_id.empty())
                    info.release_id = read_str(k.get(), "ReleaseId");
                info.ubr = read_dword(k.get(), "UBR");
            }

            SYSTEM_INFO sys{};
            ::GetNativeSystemInfo(&sys);
            switch (sys.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64: info.architecture = "x64";   break;
            case PROCESSOR_ARCHITECTURE_INTEL: info.architecture = "x86";   break;
            case PROCESSOR_ARCHITECTURE_ARM:   info.architecture = "ARM";   break;
            case PROCESSOR_ARCHITECTURE_ARM64: info.architecture = "ARM64"; break;
            default:                            info.architecture = "Unknown"; break;
            }

            if (info.major == 0 && info.product_name.empty())
                return fail<Info>({ ErrorCode::no_data,
                    "Could not read OS version (RtlGetVersion + registry both failed).", 0 });
            return info;
        }

    private:
        [[nodiscard]] static std::string read_str(HKEY k, const char* name) noexcept {
            std::array<char, 256> buf{};
            DWORD size = static_cast<DWORD>(buf.size()), type = 0;
            if (::RegQueryValueExA(k, name, nullptr, &type,
                reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS)
                return {};
            return std::string{ buf.data() };
        }
        [[nodiscard]] static std::uint32_t read_dword(HKEY k, const char* name) noexcept {
            DWORD value = 0, size = sizeof(value), type = 0;
            if (::RegQueryValueExA(k, name, nullptr, &type,
                reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS)
                return 0;
            return value;
        }
    };

    //===----------------------- Windows install date probe ------------------===//

    class InstallDateProbe {
    public:
        struct Info {
            std::uint32_t unix_epoch{ 0 };
            std::string   formatted;
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            HKEY raw{};
            const auto status = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)",
                0, KEY_READ, &raw);
            if (status != ERROR_SUCCESS)
                return fail<Info>(make_win32_error(static_cast<DWORD>(status),
                    "opening Windows NT CurrentVersion key"));
            RegKey k{ raw };

            DWORD epoch = 0, size = sizeof(epoch), type = 0;
            if (::RegQueryValueExA(k.get(), "InstallDate", nullptr, &type,
                reinterpret_cast<LPBYTE>(&epoch), &size) != ERROR_SUCCESS
                || type != REG_DWORD)
                return fail<Info>({ ErrorCode::no_data,
                    "InstallDate registry value not found.", 0 });

            Info out{ .unix_epoch = epoch };
            const std::time_t t = static_cast<std::time_t>(epoch);
            std::tm tm{};
            if (::gmtime_s(&tm, &t) == 0) {
                std::array<char, 32> buf{};
                std::strftime(buf.data(), buf.size(), "%Y-%m-%d %H:%M:%S UTC", &tm);
                out.formatted = std::string{ buf.data() };
            }
            return out;
        }
    };

    //===----------------------- Detail string helpers -----------------------===//

    namespace detail {

        [[nodiscard]] inline std::string wide_to_utf8(const wchar_t* w) {
            if (!w || !*w) return {};
            const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
            if (n <= 1) return {};
            std::string out(static_cast<std::size_t>(n - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
            return out;
        }

        [[nodiscard]] inline std::string normalize_mac(std::string_view raw) {
            std::string hex;
            hex.reserve(12);
            for (char c : raw) {
                const auto uc = static_cast<unsigned char>(c);
                if (std::isxdigit(uc)) hex.push_back(static_cast<char>(std::toupper(uc)));
            }
            if (hex.size() != 12) return {};
            std::string out;
            out.reserve(17);
            for (std::size_t i = 0; i < 12; ++i) {
                if (i > 0 && (i % 2) == 0) out.push_back('-');
                out.push_back(hex[i]);
            }
            return out;
        }

    }  // namespace detail

    //===----------------------- Code integrity probe ------------------------===//

    class CodeIntegrityProbe {
    public:
        struct Info {
            std::uint32_t flags{ 0 };

            static constexpr std::uint32_t kEnabled = 0x0001;
            static constexpr std::uint32_t kTestSign = 0x0002;
            static constexpr std::uint32_t kUmciEnabled = 0x0004;
            static constexpr std::uint32_t kUmciAuditModeEnabled = 0x0008;
            static constexpr std::uint32_t kUmciExclusionPathsEnabled = 0x0010;
            static constexpr std::uint32_t kTestBuild = 0x0020;
            static constexpr std::uint32_t kPreReleaseBuild = 0x0040;
            static constexpr std::uint32_t kDebugModeEnabled = 0x0080;
            static constexpr std::uint32_t kFlightBuild = 0x0100;
            static constexpr std::uint32_t kFlightingEnabled = 0x0200;
            static constexpr std::uint32_t kHvciKmciEnabled = 0x0400;
            static constexpr std::uint32_t kHvciKmciAuditModeEnabled = 0x0800;
            static constexpr std::uint32_t kHvciKmciStrictModeEnabled = 0x1000;
            static constexpr std::uint32_t kHvciIumEnabled = 0x2000;

            [[nodiscard]] bool kmci_enabled()    const noexcept { return flags & kEnabled; }
            [[nodiscard]] bool test_signing()    const noexcept { return flags & kTestSign; }
            [[nodiscard]] bool integrity_off()   const noexcept { return !kmci_enabled(); }
            [[nodiscard]] bool debug_mode()      const noexcept { return flags & kDebugModeEnabled; }
            [[nodiscard]] bool umci_enabled()    const noexcept { return flags & kUmciEnabled; }
            [[nodiscard]] bool hvci_enabled()    const noexcept { return flags & kHvciKmciEnabled; }

            [[nodiscard]] std::string to_summary() const {
                return std::format(
                    "flags=0x{:04X} kmci={} testsign={} debug={} umci={} hvci={}",
                    flags, kmci_enabled(), test_signing(), debug_mode(),
                    umci_enabled(), hvci_enabled());
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            struct CI_INFO { ULONG Length; ULONG CodeIntegrityOptions; };
            constexpr int kSystemCodeIntegrityInformation = 103;

            using NtQSI_t = LONG(NTAPI*)(int, PVOID, ULONG, PULONG);
            const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
                return fail<Info>(make_win32_error(::GetLastError(),
                    "resolving ntdll.dll for NtQuerySystemInformation"));
            auto* fn = reinterpret_cast<NtQSI_t>(
                ::GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (!fn)
                return fail<Info>({ ErrorCode::no_data,
                    "NtQuerySystemInformation not exported by ntdll.", 0 });

            CI_INFO ci{};
            ci.Length = sizeof(ci);
            ULONG returned = 0;
            const LONG status = fn(kSystemCodeIntegrityInformation,
                &ci, sizeof(ci), &returned);
            if (status < 0)
                return fail<Info>({ ErrorCode::api_failure,
                    std::format("NtQuerySystemInformation failed (NTSTATUS=0x{:08X}).",
                                static_cast<std::uint32_t>(status)),
                    static_cast<std::uint32_t>(status) });

            Info info;
            info.flags = ci.CodeIntegrityOptions;
            return info;
        }
    };

    //===----------------------- Secure Boot probe ---------------------------===//

    class SecureBootProbe {
    public:
        struct Info {
            bool uefi{ false };
            bool secure_boot{ false };
            bool setup_mode{ false };

            [[nodiscard]] std::string to_summary() const {
                if (!uefi) return "legacy BIOS (no Secure Boot)";
                return std::format("uefi=1 secureboot={} setupmode={}",
                    secure_boot, setup_mode);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            Info info;

            HKEY raw{};
            const auto state = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Control\SecureBoot\State)",
                0, KEY_READ, &raw);
            if (state == ERROR_FILE_NOT_FOUND) {
                return info;
            }
            if (state != ERROR_SUCCESS)
                return fail<Info>(make_win32_error(static_cast<DWORD>(state),
                    "opening SecureBoot\\State key"));
            RegKey k{ raw };
            info.uefi = true;

            DWORD value = 0, size = sizeof(value), type = 0;
            if (::RegQueryValueExA(k.get(), "UEFISecureBootEnabled", nullptr, &type,
                reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS
                && type == REG_DWORD)
                info.secure_boot = (value != 0);

            size = sizeof(value);
            if (::RegQueryValueExA(k.get(), "UEFISecureBootSetupMode", nullptr, &type,
                reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS
                && type == REG_DWORD)
                info.setup_mode = (value != 0);

            return info;
        }
    };

    //===----------------------- Time zone probe -----------------------------===//

    class TimeZoneProbe {
    public:
        struct Info {
            std::int32_t bias_minutes{ 0 };
            std::string  standard_name;
            std::string  daylight_name;
            std::string  key_name;
            bool         daylight_active{ false };

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("{}|bias={}|dst={}",
                    key_name.empty() ? standard_name : key_name,
                    bias_minutes, daylight_active);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            DYNAMIC_TIME_ZONE_INFORMATION tzi{};
            const DWORD r = ::GetDynamicTimeZoneInformation(&tzi);
            if (r == TIME_ZONE_ID_INVALID)
                return fail<Info>(make_win32_error(::GetLastError(),
                    "GetDynamicTimeZoneInformation"));
            Info out;
            out.bias_minutes = tzi.Bias;
            out.standard_name = detail::wide_to_utf8(tzi.StandardName);
            out.daylight_name = detail::wide_to_utf8(tzi.DaylightName);
            out.key_name = detail::wide_to_utf8(tzi.TimeZoneKeyName);
            out.daylight_active = (r == TIME_ZONE_ID_DAYLIGHT);
            return out;
        }
    };

    //===----------------------- Keyboard layout probe -----------------------===//

    class KeyboardLayoutProbe {
    public:
        struct Info {
            std::vector<std::string> klid_list;
            std::vector<std::uint16_t> language_ids;

            [[nodiscard]] std::string to_fingerprint() const {
                std::string out;
                for (const auto& k : klid_list) {
                    if (!out.empty()) out.push_back(',');
                    out += k;
                }
                return out;
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            std::array<HKL, 64> hkls{};
            const int n = ::GetKeyboardLayoutList(static_cast<int>(hkls.size()), hkls.data());
            if (n <= 0)
                return fail<Info>(make_win32_error(::GetLastError(),
                    "GetKeyboardLayoutList"));
            Info out;
            for (int i = 0; i < n; ++i) {
                const auto v = static_cast<std::uint32_t>(
                    reinterpret_cast<std::uintptr_t>(hkls[i]) & 0xFFFFFFFFu);
                out.klid_list.push_back(std::format("{:08X}", v));
                out.language_ids.push_back(static_cast<std::uint16_t>(v & 0xFFFFu));
            }
            return out;
        }
    };

    //===----------------------- Network MAC via WMI -------------------------===//

    class NetworkWmiProbe {
    public:
        using output_type = std::vector<MacAddress>;

        [[nodiscard]] static Result<std::vector<MacAddress>> probe() noexcept {
            detail::WmiSession ses;
            if (!ses.ok())
                return fail<std::vector<MacAddress>>(make_hresult_error(ses.hr(),
                    "initializing WMI for Win32_NetworkAdapter"));

            std::vector<MacAddress> out;
            if (HRESULT h = ses.enumerate(
                L"SELECT MACAddress FROM Win32_NetworkAdapter "
                L"WHERE MACAddress IS NOT NULL AND PhysicalAdapter = TRUE",
                [&](IWbemClassObject& obj) {
                    const auto raw = detail::get_wmi_string(obj, L"MACAddress");
                    if (raw.empty()) return;
                    auto norm = detail::normalize_mac(raw);
                    if (!norm.empty()) out.emplace_back(std::move(norm));
                }); FAILED(h))
                return fail<std::vector<MacAddress>>(make_hresult_error(h,
                    "querying Win32_NetworkAdapter"));

            if (out.empty())
                return fail<std::vector<MacAddress>>({ ErrorCode::no_data,
                    "WMI returned no physical network adapters with a MAC.", 0 });
            return out;
        }
    };

    //===----------------------- Network MAC via registry --------------------===//

    class NetworkRegistryProbe {
    public:
        struct Adapter {
            std::string subkey;
            std::string driver_desc;
            std::string net_cfg_instance_id;
            std::string network_address_override;

            [[nodiscard]] bool is_overridden() const noexcept {
                return !network_address_override.empty();
            }
        };
        using output_type = std::vector<Adapter>;

        [[nodiscard]] static Result<std::vector<Adapter>> probe() noexcept {
            HKEY raw{};
            const auto status = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318})",
                0, KEY_READ, &raw);
            if (status != ERROR_SUCCESS)
                return fail<std::vector<Adapter>>(make_win32_error(
                    static_cast<DWORD>(status),
                    "opening Net adapter Class registry key"));
            RegKey root{ raw };

            std::vector<Adapter> out;
            for (DWORD i = 0; ; ++i) {
                std::array<char, 256> name{};
                DWORD name_len = static_cast<DWORD>(name.size());
                const auto e = ::RegEnumKeyExA(root.get(), i,
                    name.data(), &name_len, nullptr, nullptr, nullptr, nullptr);
                if (e == ERROR_NO_MORE_ITEMS) break;
                if (e != ERROR_SUCCESS) continue;

                const std::string_view sv{ name.data(), name_len };
                if (sv.size() != 4 || !std::all_of(sv.begin(), sv.end(),
                    [](char c) { return c >= '0' && c <= '9'; }))
                    continue;

                HKEY sub_raw{};
                if (::RegOpenKeyExA(root.get(), name.data(), 0, KEY_READ, &sub_raw)
                    != ERROR_SUCCESS)
                    continue;
                RegKey sub{ sub_raw };

                Adapter a;
                a.subkey = std::string{ sv };
                a.driver_desc = read_str(sub.get(), "DriverDesc");
                a.net_cfg_instance_id = read_str(sub.get(), "NetCfgInstanceId");
                const auto override_raw = read_str(sub.get(), "NetworkAddress");
                if (!override_raw.empty()) {
                    auto norm = detail::normalize_mac(override_raw);
                    a.network_address_override = norm.empty() ? override_raw : norm;
                }
                if (a.net_cfg_instance_id.empty()) continue;
                out.push_back(std::move(a));
            }
            if (out.empty())
                return fail<std::vector<Adapter>>({ ErrorCode::no_data,
                    "No network adapter subkeys found in registry.", 0 });
            return out;
        }

    private:
        [[nodiscard]] static std::string read_str(HKEY k, const char* name) {
            std::array<char, 512> buf{};
            DWORD size = static_cast<DWORD>(buf.size()), type = 0;
            if (::RegQueryValueExA(k, name, nullptr, &type,
                reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS)
                return {};
            if (type != REG_SZ && type != REG_EXPAND_SZ) return {};
            return std::string{ buf.data() };
        }
    };

    //===----------------------- NVMe Identify Controller probe --------------===//

    class NvmeProbe {
    public:
        struct Info {
            std::string   serial_number;
            std::string   model_number;
            std::string   firmware;
            std::uint16_t pci_vendor_id{ 0 };
            std::uint16_t pci_subsystem_vendor_id{ 0 };

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("{}/{}/{} [VID={:04X} SSVID={:04X}]",
                    model_number, serial_number, firmware,
                    pci_vendor_id, pci_subsystem_vendor_id);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe(int drive_index = 0) noexcept {
            const std::string path = std::format(R"(\\.\PhysicalDrive{})", drive_index);
            FileHandle drive{ ::CreateFileA(path.c_str(), 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, 0, nullptr) };
            if (!drive.valid())
                return fail<Info>(make_win32_error(::GetLastError(),
                    std::format("opening physical drive {} for NVMe query", drive_index)));

            constexpr DWORD kIdentLen = 4096;
            const DWORD kBufLen = static_cast<DWORD>(
                FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters)
                + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + kIdentLen);

            std::vector<std::uint8_t> buf(kBufLen, 0);
            auto* query = reinterpret_cast<STORAGE_PROPERTY_QUERY*>(buf.data());
            query->PropertyId = StorageAdapterProtocolSpecificProperty;
            query->QueryType = PropertyStandardQuery;

            auto* psd = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(
                query->AdditionalParameters);
            psd->ProtocolType = ProtocolTypeNvme;
            psd->DataType = NVMeDataTypeIdentify;
            psd->ProtocolDataRequestValue = 1;
            psd->ProtocolDataRequestSubValue = 0;
            psd->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
            psd->ProtocolDataLength = kIdentLen;

            DWORD bytes = 0;
            if (!::DeviceIoControl(drive.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                buf.data(), kBufLen, buf.data(), kBufLen, &bytes, nullptr))
                return fail<Info>(make_win32_error(::GetLastError(),
                    std::format("IOCTL_STORAGE_QUERY_PROPERTY (NVMe Identify) on drive {}",
                        drive_index)));

            if (bytes < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR))
                return fail<Info>({ ErrorCode::parse_error,
                    "NVMe response too short for STORAGE_PROTOCOL_DATA_DESCRIPTOR.", 0 });
            const auto* desc = reinterpret_cast<const STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(buf.data());
            const auto& rsd = desc->ProtocolSpecificData;
            const std::size_t data_off =
                offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData) +
                rsd.ProtocolDataOffset;
            if (data_off + 72 > buf.size() || rsd.ProtocolDataLength < 72)
                return fail<Info>({ ErrorCode::parse_error,
                    "NVMe Identify Controller response truncated.", 0 });

            const std::uint8_t* ic = buf.data() + data_off;
            Info info;
            info.pci_vendor_id =
                static_cast<std::uint16_t>(ic[0]) |
                (static_cast<std::uint16_t>(ic[1]) << 8);
            info.pci_subsystem_vendor_id =
                static_cast<std::uint16_t>(ic[2]) |
                (static_cast<std::uint16_t>(ic[3]) << 8);
            info.serial_number = trim_ascii(ic + 4, 20);
            info.model_number = trim_ascii(ic + 24, 40);
            info.firmware = trim_ascii(ic + 64, 8);

            if (info.serial_number.empty() && info.model_number.empty())
                return fail<Info>({ ErrorCode::no_data,
                    std::format("Drive {} is not NVMe or returned empty Identify.",
                                drive_index), 0 });
            return info;
        }

    private:
        [[nodiscard]] static std::string trim_ascii(const std::uint8_t* p, std::size_t len) {
            std::size_t end = len;
            while (end > 0 && (p[end - 1] == ' ' || p[end - 1] == '\0')) --end;
            std::string out;
            out.reserve(end);
            for (std::size_t i = 0; i < end; ++i) {
                const auto c = static_cast<unsigned char>(p[i]);
                if (c >= 0x20 && c < 0x7F) out.push_back(static_cast<char>(c));
            }
            return out;
        }
    };

    //===----------------------- SetupAPI / registry helpers -----------------===//

    namespace detail {

        [[nodiscard]] inline std::string get_device_instance_id(
            HDEVINFO h, SP_DEVINFO_DATA& did) {
            std::array<char, 512> buf{};
            DWORD req = 0;
            if (::SetupDiGetDeviceInstanceIdA(h, &did, buf.data(),
                static_cast<DWORD>(buf.size()), &req))
                return std::string{ buf.data() };
            return {};
        }

        [[nodiscard]] inline std::string read_setupapi_string(
            HDEVINFO h, SP_DEVINFO_DATA& did, DWORD prop) {
            std::array<char, 1024> buf{};
            DWORD type = 0;
            if (::SetupDiGetDeviceRegistryPropertyA(h, &did, prop, &type,
                reinterpret_cast<PBYTE>(buf.data()),
                static_cast<DWORD>(buf.size()), nullptr))
                return std::string{ buf.data() };
            return {};
        }

        [[nodiscard]] inline std::uint16_t parse_hex16(std::string_view s) noexcept {
            if (s.size() < 4) return 0;
            std::uint16_t v = 0;
            for (int i = 0; i < 4; ++i) {
                const char c = s[i];
                const int x = (c >= '0' && c <= '9') ? c - '0'
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
                if (x < 0) return 0;
                v = static_cast<std::uint16_t>((v << 4) | x);
            }
            return v;
        }

        [[nodiscard]] inline std::uint16_t extract_id_token(
            std::string_view src, std::string_view tag) noexcept {
            const auto pos = src.find(tag);
            if (pos == std::string_view::npos) return 0;
            return parse_hex16(src.substr(pos + tag.size()));
        }

        [[nodiscard]] inline std::vector<std::string>
            list_reg_subkeys(HKEY parent) {
            std::vector<std::string> out;
            for (DWORD i = 0; ; ++i) {
                std::array<char, 256> name{};
                DWORD len = static_cast<DWORD>(name.size());
                const auto e = ::RegEnumKeyExA(parent, i, name.data(), &len,
                    nullptr, nullptr, nullptr, nullptr);
                if (e == ERROR_NO_MORE_ITEMS) break;
                if (e != ERROR_SUCCESS) continue;
                out.emplace_back(name.data(), len);
            }
            return out;
        }

        [[nodiscard]] inline std::string read_reg_string(HKEY k, const char* name) {
            std::array<char, 512> buf{};
            DWORD size = static_cast<DWORD>(buf.size()), type = 0;
            if (::RegQueryValueExA(k, name, nullptr, &type,
                reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS)
                return {};
            if (type != REG_SZ && type != REG_EXPAND_SZ) return {};
            return std::string{ buf.data() };
        }

    }  // namespace detail

    //===----------------------- HDD SMART probe -----------------------------===//

    class HddSmartProbe {
    public:
        struct Attribute {
            std::uint8_t  id{ 0 };
            std::uint16_t flags{ 0 };
            std::uint8_t  current{ 0 };
            std::uint8_t  worst{ 0 };
            std::uint64_t raw{ 0 };
        };
        struct Info {
            int                          drive_index{ 0 };
            std::vector<Attribute>       attributes;
            std::optional<std::uint32_t> power_on_hours;
            std::optional<std::int32_t>  temperature_c;

            [[nodiscard]] std::string to_summary() const {
                std::string s = std::format("attrs={}", attributes.size());
                if (power_on_hours) s += std::format(" poh={}", *power_on_hours);
                if (temperature_c)  s += std::format(" tempC={}", *temperature_c);
                return s;
            }

            [[nodiscard]] std::string to_fingerprint() const {
                std::string out;
                for (const auto& a : attributes) {
                    if (!out.empty()) out.push_back(',');
                    out += std::format("{:02X}", a.id);
                }
                return out;
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe(int drive_index = 0) noexcept {
            const std::string path = std::format(R"(\\.\PhysicalDrive{})", drive_index);
            FileHandle drive{ ::CreateFileA(path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, 0, nullptr) };
            if (!drive.valid())
                return fail<Info>(make_win32_error(::GetLastError(),
                    std::format("opening physical drive {} for SMART query", drive_index)));

            struct ReqBuf {
                ATA_PASS_THROUGH_EX hdr;
                UCHAR               data[512];
            } req{};
            req.hdr.Length = sizeof(ATA_PASS_THROUGH_EX);
            req.hdr.AtaFlags = ATA_FLAGS_DATA_IN;
            req.hdr.DataTransferLength = sizeof(req.data);
            req.hdr.TimeOutValue = 5;
            req.hdr.DataBufferOffset = offsetof(ReqBuf, data);
            req.hdr.CurrentTaskFile[0] = 0xD0;
            req.hdr.CurrentTaskFile[1] = 0x01;
            req.hdr.CurrentTaskFile[2] = 0x00;
            req.hdr.CurrentTaskFile[3] = 0x4F;
            req.hdr.CurrentTaskFile[4] = 0xC2;
            req.hdr.CurrentTaskFile[5] = 0x00;
            req.hdr.CurrentTaskFile[6] = 0xB0;

            DWORD bytes = 0;
            if (!::DeviceIoControl(drive.get(), IOCTL_ATA_PASS_THROUGH,
                &req, sizeof(req), &req, sizeof(req), &bytes, nullptr))
                return fail<Info>(make_win32_error(::GetLastError(),
                    std::format("IOCTL_ATA_PASS_THROUGH (SMART READ DATA) on drive {}",
                        drive_index)));

            Info info;
            info.drive_index = drive_index;
            const std::uint8_t* p = req.data + 2;
            for (int i = 0; i < 30; ++i, p += 12) {
                if (p[0] == 0) continue;
                Attribute a;
                a.id = p[0];
                a.flags = static_cast<std::uint16_t>(p[1] | (p[2] << 8));
                a.current = p[3];
                a.worst = p[4];
                a.raw = static_cast<std::uint64_t>(p[5])
                    | (static_cast<std::uint64_t>(p[6]) << 8)
                    | (static_cast<std::uint64_t>(p[7]) << 16)
                    | (static_cast<std::uint64_t>(p[8]) << 24)
                    | (static_cast<std::uint64_t>(p[9]) << 32)
                    | (static_cast<std::uint64_t>(p[10]) << 40);
                switch (a.id) {
                case 9:   info.power_on_hours =
                    static_cast<std::uint32_t>(a.raw & 0xFFFFFFFFu); break;
                case 194: info.temperature_c =
                    static_cast<std::int32_t>(a.raw & 0xFFu); break;
                default: break;
                }
                info.attributes.push_back(a);
            }
            if (info.attributes.empty())
                return fail<Info>({ ErrorCode::no_data,
                    std::format("Drive {} returned no SMART attributes "
                                "(NVMe or unsupported).", drive_index), 0 });
            return info;
        }
    };

    //===----------------------- PCI device probe ----------------------------===//

    class PciDeviceProbe {
    public:
        struct Device {
            std::string   instance_id;
            std::uint16_t vendor_id{ 0 };
            std::uint16_t device_id{ 0 };
            std::uint16_t subsys_vendor_id{ 0 };
            std::uint16_t subsys_device_id{ 0 };
            std::string   description;
            std::string   class_name;
        };
        struct Info {
            std::vector<Device>      present;
            std::vector<std::string> registry_keys;

            [[nodiscard]] std::string to_fingerprint() const {
                std::vector<std::string> ids;
                ids.reserve(present.size());
                for (const auto& d : present)
                    ids.push_back(std::format("{:04X}:{:04X}", d.vendor_id, d.device_id));
                std::sort(ids.begin(), ids.end());
                ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
                std::string out;
                for (const auto& s : ids) {
                    if (!out.empty()) out.push_back(',');
                    out += s;
                }
                return out;
            }

            [[nodiscard]] std::vector<std::string> historical_only() const {
                std::vector<std::string> out;
                for (const auto& sub : registry_keys) {
                    bool seen = false;
                    for (const auto& d : present)
                        if (d.instance_id.find(sub) != std::string::npos) {
                            seen = true; break;
                        }
                    if (!seen) out.push_back(sub);
                }
                return out;
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            Info info;
            DeviceInfoSet dis{ ::SetupDiGetClassDevsA(
                nullptr, "PCI", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES) };
            if (!dis.valid())
                return fail<Info>(make_win32_error(::GetLastError(),
                    "SetupDiGetClassDevs(PCI)"));

            SP_DEVINFO_DATA did{};
            did.cbSize = sizeof(did);
            for (DWORD i = 0; ::SetupDiEnumDeviceInfo(dis.get(), i, &did); ++i) {
                const auto id = detail::get_device_instance_id(dis.get(), did);
                if (id.empty()) continue;
                Device d;
                d.instance_id = id;
                d.vendor_id = detail::extract_id_token(id, "VEN_");
                d.device_id = detail::extract_id_token(id, "DEV_");
                const auto sub_pos = id.find("SUBSYS_");
                if (sub_pos != std::string::npos && sub_pos + 7 + 8 <= id.size()) {
                    d.subsys_device_id = detail::parse_hex16(
                        std::string_view{ id }.substr(sub_pos + 7, 4));
                    d.subsys_vendor_id = detail::parse_hex16(
                        std::string_view{ id }.substr(sub_pos + 11, 4));
                }
                d.description = detail::read_setupapi_string(
                    dis.get(), did, SPDRP_DEVICEDESC);
                d.class_name = detail::read_setupapi_string(
                    dis.get(), did, SPDRP_CLASS);
                info.present.push_back(std::move(d));
            }

            HKEY raw{};
            if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Enum\PCI)",
                0, KEY_READ, &raw) == ERROR_SUCCESS) {
                RegKey k{ raw };
                info.registry_keys = detail::list_reg_subkeys(k.get());
                std::sort(info.registry_keys.begin(), info.registry_keys.end());
            }

            if (info.present.empty() && info.registry_keys.empty())
                return fail<Info>({ ErrorCode::no_data,
                    "No PCI devices enumerated (SetupAPI + registry both empty).", 0 });

            std::sort(info.present.begin(), info.present.end(),
                [](const Device& a, const Device& b) {
                    return a.instance_id < b.instance_id;
                });
            return info;
        }
    };

    //===----------------------- USB device probe ----------------------------===//

    class UsbProbe {
    public:
        struct Device {
            std::string   instance_id;
            std::uint16_t vendor_id{ 0 };
            std::uint16_t product_id{ 0 };
            std::string   description;
            std::string   serial_token;
        };
        struct Info {
            std::vector<Device>      present;
            std::vector<std::string> registry_keys;
            std::vector<std::string> usbstor_keys;
            std::vector<std::string> swd_keys;

            [[nodiscard]] std::string to_fingerprint() const {
                std::vector<std::string> ids;
                ids.reserve(present.size());
                for (const auto& d : present)
                    if (d.vendor_id || d.product_id)
                        ids.push_back(std::format("{:04X}:{:04X}",
                            d.vendor_id, d.product_id));
                std::sort(ids.begin(), ids.end());
                ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
                std::string out;
                for (const auto& s : ids) {
                    if (!out.empty()) out.push_back(',');
                    out += s;
                }
                return out;
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            Info info;

            DeviceInfoSet dis{ ::SetupDiGetClassDevsA(
                nullptr, "USB", nullptr, DIGCF_PRESENT) };
            if (dis.valid()) {
                SP_DEVINFO_DATA did{};
                did.cbSize = sizeof(did);
                for (DWORD i = 0; ::SetupDiEnumDeviceInfo(dis.get(), i, &did); ++i) {
                    const auto id = detail::get_device_instance_id(dis.get(), did);
                    if (id.empty()) continue;
                    Device d;
                    d.instance_id = id;
                    d.vendor_id = detail::extract_id_token(id, "VID_");
                    d.product_id = detail::extract_id_token(id, "PID_");
                    d.description = detail::read_setupapi_string(
                        dis.get(), did, SPDRP_DEVICEDESC);
                    if (const auto bs = id.find_last_of('\\');
                        bs != std::string::npos)
                        d.serial_token = id.substr(bs + 1);
                    info.present.push_back(std::move(d));
                }
            }

            const auto walk = [](const char* path, std::vector<std::string>& out) {
                HKEY raw{};
                if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &raw)
                    != ERROR_SUCCESS)
                    return;
                RegKey k{ raw };
                out = detail::list_reg_subkeys(k.get());
                std::sort(out.begin(), out.end());
                };
            walk(R"(SYSTEM\CurrentControlSet\Enum\USB)", info.registry_keys);
            walk(R"(SYSTEM\CurrentControlSet\Enum\USBSTOR)", info.usbstor_keys);
            walk(R"(SYSTEM\CurrentControlSet\Enum\SWD)", info.swd_keys);

            if (info.present.empty() && info.registry_keys.empty()
                && info.usbstor_keys.empty())
                return fail<Info>({ ErrorCode::no_data,
                    "No USB devices enumerated.", 0 });

            std::sort(info.present.begin(), info.present.end(),
                [](const Device& a, const Device& b) {
                    return a.instance_id < b.instance_id;
                });
            return info;
        }
    };

    //===----------------------- Disk registry probe -------------------------===//

    class DiskRegistryProbe {
    public:
        struct Entry {
            std::string source;
            std::string device_key;
            std::string instance_key;
            std::string friendly_name;
        };
        using output_type = std::vector<Entry>;

        [[nodiscard]] static Result<std::vector<Entry>> probe() noexcept {
            std::vector<Entry> out;
            for (const char* enum_path :
                { R"(SYSTEM\CurrentControlSet\Enum\SCSI)",
                  R"(SYSTEM\CurrentControlSet\Enum\IDE)" }) {
                walk(enum_path, out);
            }
            if (out.empty())
                return fail<std::vector<Entry>>({ ErrorCode::no_data,
                    "No disk-related registry entries found.", 0 });
            std::sort(out.begin(), out.end(), [](const Entry& a, const Entry& b) {
                return std::tie(a.source, a.device_key, a.instance_key)
                    < std::tie(b.source, b.device_key, b.instance_key);
                });
            return out;
        }

    private:
        static void walk(const char* root_path, std::vector<Entry>& out) {
            HKEY root_raw{};
            if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, root_path, 0, KEY_READ, &root_raw)
                != ERROR_SUCCESS) return;
            RegKey root{ root_raw };
            const std::string source = [&] {
                std::string p{ root_path };
                const auto pos = p.find_last_of('\\');
                return pos == std::string::npos ? p : p.substr(pos + 1);
                }();

            for (const auto& dev : detail::list_reg_subkeys(root.get())) {
                HKEY dev_raw{};
                if (::RegOpenKeyExA(root.get(), dev.c_str(), 0, KEY_READ, &dev_raw)
                    != ERROR_SUCCESS) continue;
                RegKey dev_key{ dev_raw };
                for (const auto& inst : detail::list_reg_subkeys(dev_key.get())) {
                    HKEY inst_raw{};
                    if (::RegOpenKeyExA(dev_key.get(), inst.c_str(), 0, KEY_READ,
                        &inst_raw) != ERROR_SUCCESS) continue;
                    RegKey inst_key{ inst_raw };
                    Entry e;
                    e.source = source;
                    e.device_key = dev;
                    e.instance_key = inst;
                    e.friendly_name = detail::read_reg_string(inst_key.get(),
                        "FriendlyName");
                    out.push_back(std::move(e));
                }
            }
        }
    };

    //===----------------------- Monitor registry probe ----------------------===//

    class MonitorRegistryProbe {
    public:
        struct Entry {
            std::string monitor_id;
            std::string instance_key;
            std::string friendly_name;
        };
        using output_type = std::vector<Entry>;

        [[nodiscard]] static Result<std::vector<Entry>> probe() noexcept {
            HKEY raw{};
            if (const auto e = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Enum\DISPLAY)",
                0, KEY_READ, &raw); e != ERROR_SUCCESS)
                return fail<std::vector<Entry>>(make_win32_error(
                    static_cast<DWORD>(e), "opening Enum\\DISPLAY key"));
            RegKey root{ raw };

            std::vector<Entry> out;
            for (const auto& mon : detail::list_reg_subkeys(root.get())) {
                HKEY mon_raw{};
                if (::RegOpenKeyExA(root.get(), mon.c_str(), 0, KEY_READ, &mon_raw)
                    != ERROR_SUCCESS) continue;
                RegKey mon_key{ mon_raw };
                for (const auto& inst : detail::list_reg_subkeys(mon_key.get())) {
                    HKEY inst_raw{};
                    if (::RegOpenKeyExA(mon_key.get(), inst.c_str(), 0, KEY_READ,
                        &inst_raw) != ERROR_SUCCESS) continue;
                    RegKey inst_key{ inst_raw };
                    Entry e;
                    e.monitor_id = mon;
                    e.instance_key = inst;
                    e.friendly_name = detail::read_reg_string(inst_key.get(),
                        "FriendlyName");
                    out.push_back(std::move(e));
                }
            }
            if (out.empty())
                return fail<std::vector<Entry>>({ ErrorCode::no_data,
                    "No DISPLAY registry entries found.", 0 });
            std::sort(out.begin(), out.end(), [](const Entry& a, const Entry& b) {
                return std::tie(a.monitor_id, a.instance_key)
                    < std::tie(b.monitor_id, b.instance_key);
                });
            return out;
        }
    };

    //===----------------------- System UUID probe (SMBIOS Type 1) -----------===//

    class SystemUuidProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<HardwareFingerprint>(table.error());

            std::string uuid;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (!uuid.empty() || e.type != 1) return;
                if (e.length < 0x19 || e.formatted.size() < 20) return;

                std::array<std::uint8_t, 16> u{};
                std::memcpy(u.data(), e.formatted.data() + 4, 16);

                bool all_zero = true, all_ff = true;
                for (auto b : u) {
                    if (b != 0x00) all_zero = false;
                    if (b != 0xFF) all_ff = false;
                }
                if (all_zero || all_ff) return;

                uuid = std::format(
                    "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-"
                    "{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    u[3], u[2], u[1], u[0],
                    u[5], u[4],
                    u[7], u[6],
                    u[8], u[9],
                    u[10], u[11], u[12], u[13], u[14], u[15]);
                });

            if (uuid.empty())
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "SMBIOS System UUID is absent or unset.", 0 });
            return HardwareFingerprint{ uuid };
        }
    };

    //===----------------------- Baseboard probe (SMBIOS Type 2) -------------===//

    class BaseboardProbe {
    public:
        using output_type = HardwareFingerprint;

        [[nodiscard]] static Result<HardwareFingerprint> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<HardwareFingerprint>(table.error());

            std::string mfr, prod, ver, ser, asset;
            bool found = false;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (found || e.type != 2 || e.formatted.size() < 5) return;
                mfr = e.pick_string(e.formatted[0]);
                prod = e.pick_string(e.formatted[1]);
                ver = e.pick_string(e.formatted[2]);
                ser = e.pick_string(e.formatted[3]);
                asset = e.pick_string(e.formatted[4]);
                found = true;
                });
            if (!found)
                return fail<HardwareFingerprint>({ ErrorCode::no_data,
                    "SMBIOS Type-2 Baseboard record not found.", 0 });
            return HardwareFingerprint{
                std::format("{}|{}|{}|{}|{}", mfr, prod, ver, ser, asset) };
        }
    };

    //===----------------------- Chassis probe (SMBIOS Type 3) ---------------===//

    class ChassisProbe {
    public:
        struct Info {
            std::string  manufacturer;
            std::uint8_t chassis_type{ 0 };
            std::string  version;
            std::string  serial_number;
            std::string  asset_tag;

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("{}|type={}|{}|{}|{}",
                    manufacturer, chassis_type, version, serial_number, asset_tag);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<Info>(table.error());

            Info info;
            bool found = false;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (found || e.type != 3 || e.formatted.size() < 5) return;
                info.manufacturer = e.pick_string(e.formatted[0]);
                info.chassis_type = static_cast<std::uint8_t>(e.formatted[1] & 0x7F);
                info.version = e.pick_string(e.formatted[2]);
                info.serial_number = e.pick_string(e.formatted[3]);
                info.asset_tag = e.pick_string(e.formatted[4]);
                found = true;
                });
            if (!found)
                return fail<Info>({ ErrorCode::no_data,
                    "SMBIOS Type-3 System Enclosure record not found.", 0 });
            return info;
        }
    };

    //===----------------------- Memory probe (SMBIOS Type 17) ---------------===//

    class MemoryProbe {
    public:
        struct Module {
            std::string   device_locator;
            std::string   bank_locator;
            std::uint32_t size_mb{ 0 };
            std::uint16_t speed_mts{ 0 };
            std::uint8_t  memory_type{ 0 };
            std::uint8_t  form_factor{ 0 };
            std::string   manufacturer;
            std::string   serial_number;
            std::string   part_number;

            [[nodiscard]] bool populated() const noexcept { return size_mb != 0; }

            [[nodiscard]] std::string to_fingerprint() const {
                return std::format("{}/{}/{}/{}MB/{}MT",
                    manufacturer, part_number, serial_number, size_mb, speed_mts);
            }
        };
        using output_type = std::vector<Module>;

        [[nodiscard]] static Result<std::vector<Module>> probe() noexcept {
            auto table = detail::SmbiosTable::load();
            if (!table) return fail<std::vector<Module>>(table.error());

            std::vector<Module> out;
            table->for_each([&](const detail::SmbiosEntry& e) {
                if (e.type != 17 || e.formatted.size() < 11) return;
                const auto& f = e.formatted;

                Module m;
                const std::uint16_t size_raw =
                    static_cast<std::uint16_t>(f[8]) |
                    (static_cast<std::uint16_t>(f[9]) << 8);

                if (size_raw == 0 || size_raw == 0xFFFF) {
                    m.size_mb = 0;
                }
                else if (size_raw == 0x7FFF && f.size() >= 28) {
                    const std::uint32_t ext =
                        static_cast<std::uint32_t>(f[24]) |
                        (static_cast<std::uint32_t>(f[25]) << 8) |
                        (static_cast<std::uint32_t>(f[26]) << 16) |
                        (static_cast<std::uint32_t>(f[27]) << 24);
                    m.size_mb = ext & 0x7FFFFFFFu;
                }
                else {
                    m.size_mb = (size_raw & 0x8000)
                        ? static_cast<std::uint32_t>(size_raw & 0x7FFF) / 1024u
                        : static_cast<std::uint32_t>(size_raw);
                }

                m.form_factor = f[10];
                if (f.size() >= 13) m.device_locator = e.pick_string(f[12]);
                if (f.size() >= 14) m.bank_locator = e.pick_string(f[13]);
                if (f.size() >= 15) m.memory_type = f[14];
                if (f.size() >= 19)
                    m.speed_mts = static_cast<std::uint16_t>(f[17]) |
                    (static_cast<std::uint16_t>(f[18]) << 8);
                if (f.size() >= 23) {
                    m.manufacturer = e.pick_string(f[19]);
                    m.serial_number = e.pick_string(f[20]);
                    m.part_number = e.pick_string(f[22]);
                }

                out.push_back(std::move(m));
                });
            if (out.empty())
                return fail<std::vector<Module>>({ ErrorCode::no_data,
                    "No SMBIOS Type-17 Memory Device records found.", 0 });
            return out;
        }
    };

    //===----------------------- SMBIOS via WMI cross-check ------------------===//

    class SmbiosWmiProbe {
    public:
        struct Info {
            std::uint8_t  major_version{ 0 };
            std::uint8_t  minor_version{ 0 };
            std::uint32_t size{ 0 };
            HashDigest    sha256;

            [[nodiscard]] std::string to_summary() const {
                return std::format("v{}.{} size={} sha256={}",
                    major_version, minor_version, size,
                    sha256.empty() ? std::string{ "<n/a>" }
                : sha256.str().substr(0, 16));
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            detail::WmiSession ses{ L"ROOT\\WMI" };
            if (!ses.ok())
                return fail<Info>(make_hresult_error(ses.hr(),
                    "initializing ROOT\\WMI for MSSmBios_RawSMBiosTables"));

            std::vector<std::uint8_t> bytes;
            Info info;
            if (HRESULT h = ses.enumerate(
                L"SELECT SMBiosData, SmbiosMajorVersion, "
                L"SmbiosMinorVersion, Size FROM MSSmBios_RawSMBiosTables",
                [&](IWbemClassObject& obj) {
                    if (!bytes.empty()) return;
                    info.major_version = read_u8(obj, L"SmbiosMajorVersion");
                    info.minor_version = read_u8(obj, L"SmbiosMinorVersion");
                    info.size = read_u32(obj, L"Size");
                    bytes = read_bytes(obj, L"SMBiosData");
                });
                FAILED(h))
                return fail<Info>(make_hresult_error(h,
                    "ExecQuery(MSSmBios_RawSMBiosTables)"));

            if (bytes.empty())
                return fail<Info>({ ErrorCode::no_data,
                    "MSSmBios_RawSMBiosTables returned no data.", 0 });

            if (info.size == 0)
                info.size = static_cast<std::uint32_t>(bytes.size());

            if (auto h = Sha256::hash(std::as_bytes(std::span{ bytes })); h)
                info.sha256 = *h;

            return info;
        }

    private:
        [[nodiscard]] static std::uint8_t read_u8(IWbemClassObject& obj,
            const wchar_t* prop) {
            VARIANT v; ::VariantInit(&v);
            std::uint8_t out = 0;
            if (SUCCEEDED(obj.Get(prop, 0, &v, nullptr, nullptr))) {
                if (v.vt == VT_UI1) out = v.bVal;
                else if (v.vt == VT_I4)  out = static_cast<std::uint8_t>(v.lVal);
                else if (v.vt == VT_UI4) out = static_cast<std::uint8_t>(v.ulVal);
            }
            ::VariantClear(&v);
            return out;
        }

        [[nodiscard]] static std::uint32_t read_u32(IWbemClassObject& obj,
            const wchar_t* prop) {
            VARIANT v; ::VariantInit(&v);
            std::uint32_t out = 0;
            if (SUCCEEDED(obj.Get(prop, 0, &v, nullptr, nullptr))) {
                if (v.vt == VT_I4)  out = static_cast<std::uint32_t>(v.lVal);
                else if (v.vt == VT_UI4) out = v.ulVal;
                else if (v.vt == VT_I2)  out = static_cast<std::uint32_t>(v.iVal);
                else if (v.vt == VT_UI2) out = v.uiVal;
            }
            ::VariantClear(&v);
            return out;
        }

        [[nodiscard]] static std::vector<std::uint8_t>
            read_bytes(IWbemClassObject& obj, const wchar_t* prop) {
            VARIANT v; ::VariantInit(&v);
            std::vector<std::uint8_t> out;
            if (SUCCEEDED(obj.Get(prop, 0, &v, nullptr, nullptr))) {
                if ((v.vt & VT_ARRAY) && v.parray) {
                    LONG lb = 0, ub = 0;
                    ::SafeArrayGetLBound(v.parray, 1, &lb);
                    ::SafeArrayGetUBound(v.parray, 1, &ub);
                    if (ub >= lb) {
                        void* data = nullptr;
                        if (SUCCEEDED(::SafeArrayAccessData(v.parray, &data))) {
                            const auto count = static_cast<std::size_t>(ub - lb + 1);
                            out.assign(static_cast<std::uint8_t*>(data),
                                static_cast<std::uint8_t*>(data) + count);
                            ::SafeArrayUnaccessData(v.parray);
                        }
                    }
                }
            }
            ::VariantClear(&v);
            return out;
        }
    };

    //===----------------------- Installed drivers + WinTrust ----------------===//

    class InstalledDriversProbe {
    public:
        struct Driver {
            std::string    base_name;
            std::string    full_path;
            std::uintptr_t base_address{ 0 };
            bool           signature_checked{ false };
            bool           signature_valid{ false };
            std::int32_t   wintrust_status{ 0 };
        };
        struct Info {
            std::vector<Driver> drivers;
            std::uint32_t       total{ 0 };
            std::uint32_t       signed_ok{ 0 };
            std::uint32_t       signed_bad{ 0 };
            std::uint32_t       not_checked{ 0 };

            [[nodiscard]] std::string to_summary() const {
                return std::format("{} drivers (ok={} bad={} unchecked={})",
                    total, signed_ok, signed_bad, not_checked);
            }
        };
        using output_type = Info;

        [[nodiscard]] static Result<Info> probe() noexcept {
            DWORD needed = 0;
            if (!::EnumDeviceDrivers(nullptr, 0, &needed) || needed == 0)
                return fail<Info>(make_win32_error(::GetLastError(),
                    "EnumDeviceDrivers (sizing)"));

            std::vector<LPVOID> bases(needed / sizeof(LPVOID));
            if (!::EnumDeviceDrivers(bases.data(),
                static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed))
                return fail<Info>(make_win32_error(::GetLastError(),
                    "EnumDeviceDrivers"));
            bases.resize(needed / sizeof(LPVOID));

            std::array<char, MAX_PATH> sysdir{};
            const UINT sysdir_len = ::GetWindowsDirectoryA(sysdir.data(),
                static_cast<UINT>(sysdir.size()));

            Info info;
            info.drivers.reserve(bases.size());
            info.total = static_cast<std::uint32_t>(bases.size());

            for (LPVOID base : bases) {
                Driver d;
                d.base_address = reinterpret_cast<std::uintptr_t>(base);

                std::array<char, MAX_PATH> name_buf{};
                if (::GetDeviceDriverBaseNameA(base, name_buf.data(),
                    static_cast<DWORD>(name_buf.size())))
                    d.base_name = std::string{ name_buf.data() };

                std::array<char, 1024> path_buf{};
                if (::GetDeviceDriverFileNameA(base, path_buf.data(),
                    static_cast<DWORD>(path_buf.size())))
                    d.full_path = normalize_path(std::string{ path_buf.data() },
                        std::string_view{ sysdir.data(), sysdir_len });

                if (!d.full_path.empty())
                    verify_signature(d);

                if (d.signature_valid)   ++info.signed_ok;
                else if (d.signature_checked) ++info.signed_bad;
                else                          ++info.not_checked;

                info.drivers.push_back(std::move(d));
            }

            std::sort(info.drivers.begin(), info.drivers.end(),
                [](const Driver& a, const Driver& b) {
                    return a.base_name < b.base_name;
                });
            return info;
        }

    private:
        [[nodiscard]] static std::string
            normalize_path(std::string p, std::string_view sysdir) {
            constexpr std::string_view kSysRoot = "\\SystemRoot\\";
            if (p.starts_with("\\??\\")) return p.substr(4);
            if (p.starts_with(kSysRoot) && !sysdir.empty()) {
                std::string out{ sysdir };
                if (!out.empty() && out.back() != '\\') out.push_back('\\');
                out += p.substr(kSysRoot.size());
                return out;
            }
            return p;
        }

        static void verify_signature(Driver& d) {
            const int wn = ::MultiByteToWideChar(CP_ACP, 0,
                d.full_path.c_str(), -1, nullptr, 0);
            if (wn <= 1) return;
            std::wstring wpath(static_cast<std::size_t>(wn - 1), L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, d.full_path.c_str(), -1,
                wpath.data(), wn);

            WINTRUST_FILE_INFO fi{};
            fi.cbStruct = sizeof(fi);
            fi.pcwszFilePath = wpath.c_str();

            WINTRUST_DATA wd{};
            wd.cbStruct = sizeof(wd);
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_FILE;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;
            wd.pFile = &fi;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG status = ::WinVerifyTrust(
                static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
            d.signature_checked = true;
            d.signature_valid = (status == 0);
            d.wintrust_status = static_cast<std::int32_t>(status);

            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                &action, &wd);
        }
    };

    //===----------------------- Aggregated reports --------------------------===//

    struct HardwareReport {
        std::optional<HardwareFingerprint> cpu;
        std::optional<HardwareFingerprint> motherboard;
        std::optional<HardwareFingerprint> baseboard;
        std::optional<HardwareFingerprint> bios;
        std::optional<HardwareFingerprint> system_uuid;
        std::optional<ChassisProbe::Info>  chassis;
        std::vector<MemoryProbe::Module>   memory;
        std::optional<SerialNumber>        disk;
        std::optional<NvmeProbe::Info>     nvme;
        std::vector<MacAddress>            macs;
        std::vector<MacAddress>            macs_wmi;
        std::vector<NetworkRegistryProbe::Adapter> macs_registry;
        std::optional<HardwareFingerprint> gpu;
        std::vector<GpuProbe::Adapter>     gpu_details;
        std::optional<HardwareFingerprint> monitor;
        std::optional<TpmProbe::Info>      tpm;
        std::optional<HddSmartProbe::Info> hdd_smart;
        std::optional<PciDeviceProbe::Info>     pci;
        std::optional<UsbProbe::Info>           usb;
        std::vector<DiskRegistryProbe::Entry>   disk_registry;
        std::vector<MonitorRegistryProbe::Entry> monitor_registry;
        std::optional<SmbiosWmiProbe::Info>     smbios_wmi;
        std::optional<InstalledDriversProbe::Info> drivers;
        HashDigest                         combined;
        std::vector<Error>                 partial_errors;

        [[nodiscard]] bool mac_spoof_suspected() const {
            for (const auto& a : macs_registry)
                if (a.is_overridden()) return true;
            const auto canon = [](const std::vector<MacAddress>& v) {
                std::vector<std::string> s;
                s.reserve(v.size());
                for (const auto& m : v) s.push_back(m.str());
                std::sort(s.begin(), s.end());
                s.erase(std::unique(s.begin(), s.end()), s.end());
                return s;
                };
            const auto a = canon(macs);
            const auto b = canon(macs_wmi);
            if (!a.empty() && !b.empty() && a != b) return true;
            return false;
        }

        [[nodiscard]] std::size_t pci_hidden_count() const {
            return pci ? pci->historical_only().size() : 0u;
        }

        [[nodiscard]] std::uint32_t unsigned_driver_count() const {
            return drivers ? drivers->signed_bad : 0u;
        }
    };

    struct SoftwareReport {
        std::optional<SerialNumber>                   volume;
        std::optional<WindowsIdentityProbe::Identity> identity;
        std::optional<OsInfoProbe::Info>              os;
        std::optional<InstallDateProbe::Info>         install_date;
        std::optional<TimeZoneProbe::Info>            time_zone;
        std::optional<KeyboardLayoutProbe::Info>      keyboards;
        HashDigest                                    combined;
        std::vector<Error>                            partial_errors;
    };

    struct SecurityReport {
        std::optional<CodeIntegrityProbe::Info> code_integrity;
        std::optional<SecureBootProbe::Info>    secure_boot;
        std::vector<Error>                      partial_errors;

        [[nodiscard]] bool environment_compromised() const {
            if (code_integrity) {
                const auto& c = *code_integrity;
                if (c.test_signing() || c.debug_mode() || c.integrity_off())
                    return true;
            }
            return false;
        }
    };

    struct FullReport {
        HardwareReport hardware;
        SoftwareReport software;
        SecurityReport security;
        HashDigest     full;
    };

    class HwidEngine {
    public:
        [[nodiscard]] static Result<FullReport> collect() noexcept {
            FullReport rep;

            if (auto r = CpuProbe::probe(); r) rep.hardware.cpu = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = MotherboardProbe::probe(); r) {
                rep.hardware.motherboard = *r;
            }
            else {
                rep.hardware.partial_errors.push_back(r.error());
                if (auto w = MotherboardWmiProbe::probe(); w) rep.hardware.motherboard = *w;
                else rep.hardware.partial_errors.push_back(w.error());
            }

            if (auto r = BaseboardProbe::probe(); r) rep.hardware.baseboard = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = SystemUuidProbe::probe(); r) rep.hardware.system_uuid = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = ChassisProbe::probe(); r) rep.hardware.chassis = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = MemoryProbe::probe(); r) rep.hardware.memory = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = BiosProbe::probe(); r) rep.hardware.bios = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = DiskProbe::probe(0); r) {
                rep.hardware.disk = *r;
            }
            else {
                rep.hardware.partial_errors.push_back(r.error());
                if (auto w = DiskWmiProbe::probe(); w) rep.hardware.disk = *w;
                else rep.hardware.partial_errors.push_back(w.error());
            }

            if (auto r = NetworkProbe::probe(); r) rep.hardware.macs = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = NetworkWmiProbe::probe(); r) rep.hardware.macs_wmi = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = NetworkRegistryProbe::probe(); r) rep.hardware.macs_registry = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            for (int i = 0; i < 10; ++i) {
                if (auto r = NvmeProbe::probe(i); r) {
                    rep.hardware.nvme = *r;
                    break;
                }
                else if (i == 9) {
                    rep.hardware.partial_errors.push_back(r.error());
                }
            }

            if (auto r = GpuProbe::probe(); r) rep.hardware.gpu = *r;
            else rep.hardware.partial_errors.push_back(r.error());
            if (auto r = GpuProbe::details(); r) rep.hardware.gpu_details = *r;

            if (auto r = MonitorProbe::probe(); r) rep.hardware.monitor = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = TpmProbe::probe(); r) rep.hardware.tpm = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = VolumeProbe::probe('C'); r) rep.software.volume = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = WindowsIdentityProbe::probe(); r) rep.software.identity = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = OsInfoProbe::probe(); r) rep.software.os = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = InstallDateProbe::probe(); r) rep.software.install_date = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = TimeZoneProbe::probe(); r) rep.software.time_zone = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = KeyboardLayoutProbe::probe(); r) rep.software.keyboards = *r;
            else rep.software.partial_errors.push_back(r.error());

            if (auto r = CodeIntegrityProbe::probe(); r) rep.security.code_integrity = *r;
            else rep.security.partial_errors.push_back(r.error());

            if (auto r = SecureBootProbe::probe(); r) rep.security.secure_boot = *r;
            else rep.security.partial_errors.push_back(r.error());

            if (auto r = HddSmartProbe::probe(0); r) rep.hardware.hdd_smart = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = PciDeviceProbe::probe(); r) rep.hardware.pci = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = UsbProbe::probe(); r) rep.hardware.usb = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = DiskRegistryProbe::probe(); r) rep.hardware.disk_registry = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = MonitorRegistryProbe::probe(); r) rep.hardware.monitor_registry = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = SmbiosWmiProbe::probe(); r) rep.hardware.smbios_wmi = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto r = InstalledDriversProbe::probe(); r) rep.hardware.drivers = *r;
            else rep.hardware.partial_errors.push_back(r.error());

            if (auto h = Sha256::hash(build_hw_input(rep.hardware)); h) rep.hardware.combined = *h;
            else return fail<FullReport>(h.error());

            if (auto h = Sha256::hash(build_sw_input(rep.software)); h) rep.software.combined = *h;
            else return fail<FullReport>(h.error());

            const std::string mix =
                rep.hardware.combined.str() + "::" + rep.software.combined.str();
            if (auto h = Sha256::hash(mix); h) rep.full = *h;
            else return fail<FullReport>(h.error());

            return rep;
        }

    private:
        [[nodiscard]] static std::string build_hw_input(const HardwareReport& r) {
            std::string macs_joined;
            for (const auto& m : r.macs) {
                if (!macs_joined.empty()) macs_joined += ',';
                macs_joined += m.str();
            }
            std::string mem_joined;
            for (const auto& m : r.memory) {
                if (!m.populated()) continue;
                if (!mem_joined.empty()) mem_joined += ',';
                mem_joined += m.to_fingerprint();
            }
            std::string disk_reg_joined;
            for (const auto& e : r.disk_registry) {
                if (!disk_reg_joined.empty()) disk_reg_joined += ',';
                disk_reg_joined += e.source + ':' + e.device_key;
            }
            std::string mon_reg_joined;
            for (const auto& e : r.monitor_registry) {
                if (!mon_reg_joined.empty()) mon_reg_joined += ',';
                mon_reg_joined += e.monitor_id;
            }
            return std::format(
                "CPU={}|MB={}|BB={}|UUID={}|CHASSIS={}|MEM={}|BIOS={}|DISK={}|MAC={}|"
                "GPU={}|MON={}|TPM={}|PCI={}|DREG={}|MREG={}|SMBW={}",
                r.cpu ? r.cpu->str() : std::string{},
                r.motherboard ? r.motherboard->str() : std::string{},
                r.baseboard ? r.baseboard->str() : std::string{},
                r.system_uuid ? r.system_uuid->str() : std::string{},
                r.chassis ? r.chassis->to_fingerprint() : std::string{},
                mem_joined,
                r.bios ? r.bios->str() : std::string{},
                r.disk ? r.disk->str() : std::string{},
                macs_joined,
                r.gpu ? r.gpu->str() : std::string{},
                r.monitor ? r.monitor->str() : std::string{},
                r.tpm ? r.tpm->to_fingerprint() : std::string{},
                r.pci ? r.pci->to_fingerprint() : std::string{},
                disk_reg_joined,
                mon_reg_joined,
                r.smbios_wmi ? r.smbios_wmi->sha256.str() : std::string{});
        }

        [[nodiscard]] static std::string build_sw_input(const SoftwareReport& r) {
            const auto& id = r.identity;
            return std::format("VOL={}|PID={}|HOST={}|SID={}|OS={}|INST={}|TZ={}|KB={}",
                r.volume ? r.volume->str() : std::string{},
                id ? id->product_id : std::string{},
                id ? id->computer_name : std::string{},
                id ? id->user_sid : std::string{},
                r.os ? r.os->to_fingerprint() : std::string{},
                r.install_date ? std::to_string(r.install_date->unix_epoch) : std::string{},
                r.time_zone ? r.time_zone->to_fingerprint() : std::string{},
                r.keyboards ? r.keyboards->to_fingerprint() : std::string{});
        }
    };

}  // namespace chp3