#pragma once

/// @file

#include <string>
#include <vector>
#include <functional>
#include <map>
#include "DpdkDeviceList.h"
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

        //std::function<void(long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> m_callback;

        //std::function<void(long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> m_callback;

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
         * @param[in] devs the PCI address of the devices
         * @param[in] queues the number of RX queues used
         * @param[in] jvm the pointer to JavaVM object
         * @param[in] clz the Java class name for callback
         * @param[in] mtd the Java class static method for callback
         * @param[in] sig the Java class static method signature for callback
         * @return true if can start the processing
         */
        bool startProcess(const std::vector<std::string> devs, const uint16_t queues, const void* jvm, const std::string& clz, const std::string& mtd, const std::string& sig);

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
