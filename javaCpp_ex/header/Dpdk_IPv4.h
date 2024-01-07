#ifndef PCAPPP_DPDK_IPv4
#define PCAPPP_DPDK_IPv4

/// @file

#include <string>
#include <vector>
#include <map>
#include "DpdkDeviceList.h"
#include "IPv4Layer.h"
#include "IPReassembly.h"

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
    class Dpdk_Dev_Rx_Stats
    {
    public:
        long long tv_sec;
        uint64_t packets;
        uint64_t bytes;
        uint64_t packetsPerSec;
        uint64_t bytesPerSec;
        uint64_t rxDrop;
        uint64_t rxErrs;
        uint64_t rxMbufAllocFail;
    };

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
        std::map<std::string, Dpdk_Dev_Rx_Stats*> stats;

	public:
        /**
         * @param[in] app application name
         * @param[in] args DPDK initialization parameters
         * @param[in] maxIPReassembly max pending IP re-assembly segments
         * @param[in] masterCore the core used by DPDK master thread
         * @param[in] svcCores the core used by DPDK service threads
         * @param[in] mBufPoolSizePerDevice mBuf pool size for each DPDK device
         * @param[in] debug turn on debug log
         */
		Dpdk_Ipv4(const std::string& app, const std::vector<std::string>& args, const size_t maxIPReassembly, const uint8_t masterCore, const std::vector<int> svcCores, const uint32_t mBufPoolSizePerDevice, const bool debug);

		~Dpdk_Ipv4();

        /**
         * start the DPDK with callback with new thread
         * @param[in] ptr a pointer to JNI object JavaVM
         * @param[in] devs the PCI address of the devices
         * @param[in] queues the number of RX queues used
         * @param[in] cbClz the classname of the callback
         * @param[in] cbMtd the method of the callback class
         * @param[in] cbSig the signature of the callback method
         * @return true if can start the processing
         */
        bool startProcess(void* ptr, const std::vector<std::string> devs, const uint16_t queues, const std::string& cbClz, const std::string& cbMtd, const std::string& cbSig);

        /**
         * stop the DPDK
         */
        void stopProcess();

        /**
         * get the device stats
         * @param[in] dev the PCI address of the device
         * @return the stats
         */
        Dpdk_Dev_Rx_Stats* getDeviceStats(const std::string& dev);
	};
}

#endif // PCAPPP_DPDK_IPv4
