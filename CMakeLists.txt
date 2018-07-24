cmake_minimum_required(VERSION 3.10)
project(Cxx11SGXDemo2)

set(CMAKE_CXX_STANDARD 11)
link_libraries(crypto)

include_directories(SSPM_VERSIONS)
include_directories(Enclave)
include_directories(App)


add_executable(Cxx11SGXDemo2
        App/TrustedLibrary/Libcxx.cpp
        App/App.cpp
        App/App.h
        App/Enclave_u.c
        App/Enclave_u.h
        Enclave/TrustedLibrary/Ecalls.cpp
        Enclave/Enclave.config.xml
        Enclave/Enclave.cpp
        Enclave/Enclave.edl
        Enclave/Enclave.h
        Enclave/Enclave.lds
        Enclave/Enclave.o
        Enclave/Enclave_debug.lds
        Enclave/Enclave_private.pem
        Enclave/Enclave_t.c
        Enclave/Enclave_t.h
        Enclave/Enclave_t.o
        app
        enclave.signed.so
        enclave.so
        Makefile
        README.txt App/SSPM.cpp)
