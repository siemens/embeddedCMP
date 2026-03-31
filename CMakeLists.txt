cmake_minimum_required(VERSION 3.14)
project(embedded_cmp
        DESCRIPTION "Embedded CMP"
        LANGUAGES C
        VERSION 1.0.0)

option(SELFHOSTED "Set to '1' to build self-hosted binary, '0' by default makes a library" 1)

include(cmake/splint.cmake)
include(FetchContent)

# Cross compiling with cmake (a possible example)
#set(tools /Users/ptorelli/dev/gcc-arm-none-eabi-8-2018-q4-major)
#set(CMAKE_C_COMPILER ${tools}/bin/arm-none-eabi-gcc)
#set(CMAKE_RANLIB ${tools}/bin/arm-none-eabi-ranlib)
#set(CMAKE_AR ${tools}/bin/arm-none-eabi-ar)
#set(CMAKE_LINKER ${tools}/bin/arm-none-eabi-ld)
#set(CMAKE_STRIP ${tools}/bin/arm-none-eabi-strip)
#set(CMAKE_NM ${tools}/bin/arm-none-eabi-nm)
#set(CMAKE_OBJDUMP ${tools}/bin/arm-none-eabi-objdump)

set(CMAKE_C_FLAGS "-pedantic -Wall -Wno-variadic-macro-arguments-omitted -Wno-gnu-zero-variadic-macro-arguments -O3")

# -- Logging --

option(EMBEDDEDCMP_DEBUG "Enable CMP Debugging" OFF)

# -- MBEDTLS --

option(USE_PKCS11_HELPER_LIBRARY "Build mbed TLS with the pkcs11-helper library." OFF)
option(ENABLE_ZLIB_SUPPORT "Build mbed TLS with zlib library." OFF)
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)
# option(USE_STATIC_MBEDTLS_LIBRARY "Build mbed TLS static library." OFF)
# option(USE_SHARED_MBEDTLS_LIBRARY "Build mbed TLS shared library." ON)

# Use custom config file for Mbed TLS
# set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls_config.h"
# CACHE STRING "Custom Mbed TLS config" FORCE)

FetchContent_Declare(
   mbedtls
   GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
   GIT_TAG v3.6.4
)

FetchContent_MakeAvailable(mbedtls)

# set(CMAKE_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/lib)

#if (CMAKE_SYSTEM MATCHES "OpenBSD")
#	option(LINK_WITH_PTHREAD "Explicitly link mbed TLS library to pthread." on)
#endif()

set(MBEDTLS_LIBRARIES "mbedtls" "mbedx509")

include_directories(include)

add_compile_options(-g)

if (SELFHOSTED)
    include_directories(program)
    set(SOURCE
		library/cmpcl_ctx.c
		library/cmpcl_lib.c
		library/cmpcl_read.c
		library/cmpcl_ses.c
		library/cmpcl_write.c
		program/cmp_main.c
		program/cmpclient.c
		program/mbedtls_transport.c
		program/credential_storage.c
    )
#    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_executable(embedded_cmp ${SOURCE})
    target_link_libraries(embedded_cmp "mbedtls" "mbedx509")
    set_target_properties(embedded_cmp PROPERTIES INSTALL_RPATH mbedtls)
    include(CTest)
    add_test(NAME TestImprinting COMMAND embedded_cmp -i WORKING_DIRECTORY ..)
    add_test(NAME TestBootstrapping COMMAND embedded_cmp -c WORKING_DIRECTORY ..)
    add_test(NAME TestKeyupdate COMMAND embedded_cmp -k WORKING_DIRECTORY ..)
else()
    set(SOURCE
		library/cmpcl_ctx.c
		library/cmpcl_lib.c
		library/cmpcl_read.c
		library/cmpcl_ses.c
		library/cmpcl_write.c
    )
    add_library(embedded_cmp ${SOURCE})
endif()

add_splint(embedded_cmp ${SOURCE})

