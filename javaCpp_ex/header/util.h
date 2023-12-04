#ifndef PCAPPP_JAVACC_UTIL
#define PCAPPP_JAVACC_UTIL

/// @file

#include "RawPacket.h"
#include "IPv4Layer.h"
#include "ProtocolType.h"
#include "IPReassembly.h"

pcpp::Packet* getIPv4Layer(pcpp::RawPacket *rp, pcpp::IPReassembly *reassembly);

#endif // PCAPPP_JAVACC_UTIL
