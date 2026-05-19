cmake_minimum_required(VERSION 3.20)
project(ctx3_hwid_parser VERSION 1.0.0 LANGUAGES CXX)

# Require C++20
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Header-only library
add_library(chp3 INTERFACE)
target_include_directories(chp3 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Include)

# Executable
add_executable(ctx3_hwid src/main.cpp)

# Link to header-only library
target_link_libraries(ctx3_hwid PRIVATE chp3)

# Windows-specific requirements
if(WIN32)
    target_compile_definitions(ctx3_hwid PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
    
    target_link_libraries(ctx3_hwid PRIVATE
        iphlpapi
        dxgi
        setupapi
        advapi32
        bcrypt
        wbemuuid
        ole32
        oleaut32
        tbs
        wintrust
        psapi
    )
endif()

# MSVC-specific settings
if(MSVC)
    target_compile_options(ctx3_hwid PRIVATE /W4 /EHsc)
    # Enable C++23 std::println if available, otherwise fallback
    target_compile_features(ctx3_hwid PRIVATE cxx_std_20)
endif()
