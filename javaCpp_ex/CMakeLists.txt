add_library(
  javaCpp_ex SHARED
  src/PcapFile_IPv4.cpp
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/Dpdk_IPv4.cpp>
  src/util.cpp)

set(public_headers
    header/PcapFile_IPv4.h)

if(PCAPPP_USE_DPDK)
  list(
    APPEND
    public_headers
    header/Dpdk_IPv4.h)
endif()

# Set the public header that will be installed
set_property(TARGET javaCpp_ex PROPERTY PUBLIC_HEADER ${public_headers})

target_include_directories(
  javaCpp_ex
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header> $<INSTALL_INTERFACE:include/pcapplusplus>)

target_link_libraries(
  javaCpp_ex
  PUBLIC Common++
         Packet++
         Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS javaCpp_ex
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()

set_property(TARGET javaCpp_ex PROPERTY OUTPUT_NAME "javaCpp_ex")
set_property(TARGET javaCpp_ex PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET javaCpp_ex PROPERTY COMPILE_WARNING_AS_ERROR ON)
