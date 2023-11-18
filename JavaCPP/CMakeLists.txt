add_library(
  JavaCPP SHARED
  src/PcapFile_IPv4.cpp
  src/util.cpp)

set(public_headers
    header/PcapFile_IPv4.h)

# Set the public header that will be installed
set_property(TARGET JavaCPP PROPERTY PUBLIC_HEADER ${public_headers})

target_include_directories(
  JavaCPP
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header> $<INSTALL_INTERFACE:include/pcapplusplus>)

target_link_libraries(
  JavaCPP
  PUBLIC Common++
         Packet++
         Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS JavaCPP
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()

set_property(TARGET JavaCPP PROPERTY OUTPUT_NAME "JavaCPP")
set_property(TARGET JavaCPP PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET JavaCPP PROPERTY COMPILE_WARNING_AS_ERROR ON)
