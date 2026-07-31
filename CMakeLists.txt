cmake_minimum_required(VERSION 3.14)

# set(CMAKE_VERBOSE_MAKEFILE ON)

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

add_compile_options(-pedantic -Werror)
add_compile_options(-Wall -Wno-gnu-zero-variadic-macro-arguments) # -Wno-variadic-macro-arguments-omitted

# must do add_compile_options() before add_library() and add_executable() see
# https://stackoverflow.com/questions/40516794/cmake-not-applying-compile-option-using-add-compile-options
if(DEFINED ENV{NDEBUG} OR NOT CMAKE_BUILD_TYPE MATCHES Debug)
  if(DEFINED ENV{NDEBUG})
    message(STATUS "Setting build type to 'Release' because NDEBUG was set.")
  elseif(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'Release' by default.")
  endif()
  set(CMAKE_BUILD_TYPE Release  # automatically leads to CFLAGS += -DNDEBUG -O2
      CACHE STRING "Choose the type of build." FORCE)
else()
  set(CMAKE_BUILD_TYPE Debug  # automatically leads to CFLAGS += -g3
      CACHE STRING "Choose the type of build." FORCE)
    if(NOT MSVC)
      add_compile_options(-O0) # workaround in case not added by default
    endif()
  set(SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
  add_compile_options(${SANITIZER_FLAGS})
  link_libraries(${SANITIZER_FLAGS})

  if(UNIX AND NOT APPLE)
    set(COVERAGE_FLAGS --coverage -fprofile-arcs)
    add_compile_options(${COVERAGE_FLAGS})
    link_libraries(${COVERAGE_FLAGS})
  endif()
endif()
message(STATUS "build mode: ${CMAKE_BUILD_TYPE}")


# -- Logging --

option(EMBEDDEDCMP_DEBUG "Enable CMP Debugging" OFF)
if(EMBEDDEDCMP_DEBUG)
  add_compile_options(-DEMBEDDEDCMP_DEBUG=1)
endif()

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
                # implementation of single-shot and high-level API:
		program/cmpcl_single.c
		program/cmpcl_high.c
		program/mbedtls_transport.c
		program/credential_storage.c
                # CLI for testing:
		# program/cmp_main_single.c # CLI for testing single-shot API
		program/cmp_main.c # high-level API
    )
#    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_executable(embedded_cmp ${SOURCE})
    target_link_libraries(embedded_cmp "mbedtls" "mbedx509")
    set_target_properties(embedded_cmp PROPERTIES INSTALL_RPATH mbedtls)
    include(CTest)
    file(WRITE "${CMAKE_BINARY_DIR}/CTestCustom.cmake"
        "set(CTEST_CUSTOM_PRE_TEST \"${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target embedded_cmp\")\n"
    )
    add_test(NAME TestImprinting.   COMMAND embedded_cmp -i WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    add_test(NAME TestBootstrapping COMMAND embedded_cmp -c WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    add_test(NAME TestKeyupdate     COMMAND embedded_cmp -k WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    add_test(NAME TestP10CR         COMMAND embedded_cmp -p WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}) # cannot update the resulting cert because the private key is not available here
    add_custom_target(check
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS embedded_cmp
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
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

