cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)
link_directories (${DBUSINTERFACE_LIBRARIES})

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

find_package (PkgConfig REQUIRED)

pkg_check_modules (SYSTEMD libsystemd REQUIRED)
include_directories (${SYSTEMD_INCLUDE_DIRS})
link_directories (${SYSTEMD_LIBRARY_DIRS})

# import sdbusplus
pkg_check_modules (SDBUSPLUSPLUS sdbusplus REQUIRED)
include_directories (${SDBUSPLUSPLUS_INCLUDE_DIRS})
link_directories (${SDBUSPLUSPLUS_LIBRARY_DIRS})
find_program (SDBUSPLUSPLUS sdbus++)

# import sdeventplus
pkg_check_modules (SDEVENTPLUSPLUS sdeventplus REQUIRED)
include_directories (${SDEVENTPLUSPLUS_INCLUDE_DIRS})
link_directories (${SDEVENTPLUSPLUS_LIBRARY_DIRS})
find_program (SDEVENTPLUSPLUS sdevent++)


# phosphor-dbus-interfaces
pkg_check_modules (DBUSINTERFACE phosphor-dbus-interfaces REQUIRED)
include_directories (${DBUSINTERFACE_INCLUDE_DIRS})
link_directories (${DBUSINTERFACE_LIBRARY_DIRS})

# boost
include_directories (SYSTEM ${CMAKE_BINARY_DIR}/boost-src)
set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/boost-src ${CMAKE_PREFIX_PATH})
add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)
add_definitions (-DBOOST_ASIO_DISABLE_THREADS)

set (SRC_FILES src/main.cpp src/component_integrity.cpp src/trusted_component.cpp
        src/certificate.cpp)

SET(src_spdm_requester_emu_copy
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_emu.c
)

#SET(src_test_c_func src/test_c_header.c)

SET(src_spdm_requester_emu_helper
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_spdm.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_authentication.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_measurement.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_session.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_pci_doe.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_mctp.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu/spdm_requester_tcp.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

ADD_LIBRARY(spdm_requester_emu_helper_lib STATIC ${src_spdm_requester_emu_helper})
#ADD_LIBRARY(test_c_lib STATIC ${src_test_c_func})

SET(spdm_requester_emu_LIBRARY
    spdm_requester_emu_helper_lib
    memlib
    debuglib
    spdm_requester_lib
    spdm_common_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_transport_pcidoe_lib
    spdm_transport_tcp_lib
    spdm_transport_none_lib
    spdm_device_secret_lib_sample
    mctp_requester_lib
    pci_doe_requester_lib
    pci_ide_km_requester_lib
    pci_tdisp_requester_lib
    cxl_ide_km_requester_lib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    cryptlib_${CRYPTO}
    ${CRYPTO_LIB_PATHS}
    rnglib
    malloclib
    platform_lib
)


#include_directories (${CMAKE_CURRENT_BINARY_DIR})
add_executable (dbus_agent_spdm_req ${SRC_FILES})
#target_link_libraries(dbus_agent_spdm_req test_c_lib)
target_link_libraries(dbus_agent_spdm_req ${spdm_requester_emu_LIBRARY})
target_link_libraries(dbus_agent_spdm_req ${spdm_requester_emu_LIBRARY})
target_link_libraries (dbus_agent_spdm_req ${SYSTEMD_LIBRARIES})
target_link_libraries (dbus_agent_spdm_req ${DBUSINTERFACE_LIBRARIES})
target_link_libraries (dbus_agent_spdm_req ${SDBUSPLUSPLUS_LIBRARIES})
target_link_libraries (dbus_agent_spdm_req phosphor_logging)

#set_target_properties(dbus_agent_spdm_req PROPERTIES LINK_LANGUAGE CXX)
ADD_EXECUTABLE(spdm_requester_emu_copy ${src_spdm_requester_emu_copy})
target_link_libraries(spdm_requester_emu_copy ${spdm_requester_emu_LIBRARY})

install (TARGETS dbus_agent_spdm_req DESTINATION bin)
install (TARGETS spdm_requester_emu_copy DESTINATION bin)
