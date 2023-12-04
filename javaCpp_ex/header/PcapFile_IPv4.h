#pragma once

/// @file

#include <string.h>
#include <functional>
#include "PcapFileDevice.h"
#include "IPReassembly.h"

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	/**
	 * @class PcapFileInIpV4Out
	 * A class to read in PCAP file and produce the IPv4 packets
	 */
	class PcapFileInIpV4Out
	{
    private:
		IFileReaderDevice* m_fileDevice;
		IPReassembly m_reassembly;
        //std::function<void(bool, long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> m_callback;

	public:
        /*
         * @param[in] fileName the PCAP / PCAP-NG file
         * @param[in] isNg true if it is PCAP-NG file
         * @param[in] maxIPReassembly max pending IP re-assembly segments
         */
		PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly);

		~PcapFileInIpV4Out();

        /**
         * start the file reading with BPF filter and callback with new thread
         * @param[in] bpfFilter the BPF filter
         * @param[in] jvm the pointer to JavaVM object
         * @param[in] clz the Java class name for callback
         * @param[in] mtd the Java class static method for callback
         * @param[in] sig the Java class static method signature for callback
         * @return nothing
         */
        void startProcess(const std::string& bpfFilter, const void* jvm, const std::string& clz, const std::string& mtd, const std::string& sig);
	};
}

