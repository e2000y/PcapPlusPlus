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
		IFileReaderDevice *fileDevice = NULL;
		IPReassembly  reassembly;

		void stop();

	public:
		PcapFileInIpV4Out(const std::string& fileName, const bool isNg, const std::string& bpfFilter, size_t maxIPReassembly);

		virtual ~PcapFileInIpV4Out() { stop(); }

		/**
                 * Read the next IPv4 packet from the file.
                 * @return the reference to IPv4Layer or NULL if the file cannot be read anymore
                 * or if reached end-of-file
                 */
                IPv4Layer*  getNextPacket();
	};
}

#endif // PCAPPP_PCAPFILE_IPv4
