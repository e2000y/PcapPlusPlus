#ifndef PCAPPP_PCAPFILE_IPv4
#define PCAPPP_PCAPFILE_IPv4

/// @file

#include <string.h>
#include <time.h>
#include <thread>
#include "PcapFileDevice.h"
#include "IPv4Layer.h"
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
		IFileReaderDevice* fileDevice;
		IPReassembly reassembly;

	public:
		PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly);

		~PcapFileInIpV4Out();

        /**
         * start the file reading with BPF filter and callback with new thread
         * @param[in] bpfFilter the BPF filter
         * @param[in] callback the callback function that take in flag, time and IPv4Layer as parameter
         * @return nothing
         */
        void startProcess(const std::string& bpfFilter, void (*callback)(bool isEnd, long long time, IPv4Layer* layer));
	};
}

#endif // PCAPPP_PCAPFILE_IPv4
