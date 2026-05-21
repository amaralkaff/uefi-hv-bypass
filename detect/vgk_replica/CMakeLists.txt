cmake_minimum_required(VERSION 3.20)
project(vgk_probe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /wd4204 /wd4201 /wd4324 /wd4996 /O2)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -O2)
endif()

add_executable(vgk_probe
    src/main.c
    src/cpuid_checks.c
    src/timing_checks.c
    src/msr_cr_checks.c
    src/nic_smbios_checks.c
)

target_include_directories(vgk_probe PRIVATE include)

if(WIN32)
    target_link_libraries(vgk_probe PRIVATE iphlpapi shell32 ole32)
endif()

install(TARGETS vgk_probe RUNTIME DESTINATION bin)
