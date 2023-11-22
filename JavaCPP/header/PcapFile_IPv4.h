#ifndef PCAPPP_PCAPFILE_IPv4
#define PCAPPP_PCAPFILE_IPv4

/// @file

#include <string.h>
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
		IFileReaderDevice *fileDevice;
		IPReassembly  reassembly;

	public:
		PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly);

		~PcapFileInIpV4Out();

        /**
         * prepare starting the file reading
         * @return true if file can be opened for reading
         * @param[in] bpfFilter the BPF filter
         */
        bool start(const std::string& bpfFilter);

		/**
         * Read the next IPv4 packet from the file.
         * @return the reference to IPv4Layer or NULL if the file cannot be read anymore
         * or if reached end-of-file
         */
        IPv4Layer* getNextPacket();
	};
}

#endif // PCAPPP_PCAPFILE_IPv4
