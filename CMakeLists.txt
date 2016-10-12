project(parsecat)

cmake_minimum_required(VERSION 3.5)

# Create the compile command database for clang by default
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

include(CheckCCompilerFlag)
if (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang)")

    # add -Wconversion ?
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wmissing-prototypes -Wdeclaration-after-statement")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wfloat-equal -Wpointer-arith -Wwrite-strings -Wformat-security")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-format-attribute -Wcast-align -Wcast-qual")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=pointer-arith -Werror=declaration-after-statement")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=implicit-function-declaration -Werror=write-strings")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=int-to-pointer-cast -Werror=pointer-to-int-cast")
    # -Werror=strict-aliasing is broken
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstrict-aliasing -Wstrict-aliasing=2")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstrict-overflow -Wstrict-overflow=5 -Werror=strict-overflow")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

    # with -fPIC
    check_c_compiler_flag("-fPIC" WITH_FPIC)
    if (WITH_FPIC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    endif (WITH_FPIC)

    if (CMAKE_BUILD_TYPE)
        string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)
        if (CMAKE_BUILD_TYPE_LOWER MATCHES (release|relwithdebinfo|minsizerel))
            check_c_compiler_flag("-Wp,-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE)
            if (WITH_FORTIFY_SOURCE)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wp,-D_FORTIFY_SOURCE=2")
            endif (WITH_FORTIFY_SOURCE)

            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=uninitialized")
        endif()
    endif()
endif (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang)")

find_package(GnuTLS REQUIRED)
find_package(Libtasn1 REQUIRED)

add_subdirectory(src)
