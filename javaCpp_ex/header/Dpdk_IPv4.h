#ifndef PCAPPP_DPDK_IPv4
#define PCAPPP_DPDK_IPv4

/// @file

#include <string>
#include <vector>
#include "DpdkDeviceList.h"
#include "IPv4Layer.h"
#include "IPReassembly.h"

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	/**
	 * @class Dpdk_Ipv4
	 * A class to use DPDK to get data and produce the IPv4 packets
	 */
	class Dpdk_Ipv4
	{
    private:
        CoreMask m_coreMask;
        uint32_t m_mBufPoolSizePerDevice;
        std::vector<SystemCore> m_coresToUse;
		IPReassembly m_reassembly;

	public:
        /**
         * @param[in] app application name
         * @param[in] args DPDK initialization parameters
         * @param[in] maxIPReassembly max pending IP re-assembly segments
         * @param[in] masterCore the core used by DPDK master thread
         * @param[in] coreMask the core used by captured thread
         * @param[in] mBufPoolSizePerDevice mBuf pool size for each DPDK device
         * @param[in] debug turn on debug log
         */
		Dpdk_Ipv4(const std::string& app, const std::vector<std::string>& args, const size_t maxIPReassembly, const uint8_t masterCore, const CoreMask coreMask, const uint32_t mBufPoolSizePerDevice, const bool debug);

		~Dpdk_Ipv4();

        /**
         * start the DPDK with callback with new thread
         * @param[in] devs the PCI address of the devices
         * @param[in] callback the callback function that take in flag, time and IPv4Layer as parameter
         * @return true if can start the processing
         */
        bool startProcess(const std::vector<std::string> devs, void (*callback)(bool isEnd, long long time, IPv4Layer* layer));

        /**
         * stop the DPDK
         */
        void stopProcess();
	};
}

#endif // PCAPPP_DPDK_IPv4
