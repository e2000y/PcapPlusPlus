#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

#include <time.h>
#include <thread>
#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "ProtocolType.h"
#include "PcapFile_IPv4.h"
#include "util.h"

namespace pcpp
{

void processFile(IFileReaderDevice* fileDevice, IPReassembly reassembly, std::function<void(bool, long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> callback)
{
    RawPacket rawPacket = RawPacket();

    while (fileDevice->getNextPacket(rawPacket))
    {
        Packet* pkt = getIPv4Layer(&rawPacket, &reassembly);

        if (pkt != nullptr)
        {
            IPv4Layer* ipLayer = pkt->getLayerOfType<IPv4Layer>(true);

            if (ipLayer != nullptr)
            {
                timespec t = rawPacket.getPacketTimeStamp();

                long long time = (t.tv_sec * 1000L) + (t.tv_nsec / 1000000L);

                callback(false, time, ipLayer->getIPv4Header()->ipSrc, ipLayer->getIPv4Header()->ipDst, ipLayer->getIPv4Header()->protocol, ipLayer->getLayerPayloadSize(), ipLayer->getLayerPayload());
            }

            delete pkt;
        }

        rawPacket.clear();
    }

    PCPP_LOG_INFO("PCAP / PCAP-NG end of file reached");

    callback(true, 0L, 0, 0, 0, 0, nullptr);
}

PcapFileInIpV4Out::PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly) :
	m_reassembly(nullptr, nullptr, maxIPReassembly)
{
	if (isNg)
		m_fileDevice = new PcapNgFileReaderDevice(fileName);
	else
		m_fileDevice = new PcapFileReaderDevice(fileName);
}

PcapFileInIpV4Out::~PcapFileInIpV4Out()
{
    if (m_fileDevice != nullptr)
    {
        m_fileDevice->close();

        delete m_fileDevice;

        m_fileDevice = nullptr;
    }
}

void PcapFileInIpV4Out::startProcess(const std::string& bpfFilter, std::function<void(bool, long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> callback)
{
	if (m_fileDevice->open())
    {
	    if (!bpfFilter.empty())
	    	m_fileDevice->setFilter(bpfFilter);

        std::thread(&processFile, m_fileDevice, m_reassembly, callback).detach();
    }
    else
    {
		PCPP_LOG_ERROR("Cannot open PCAP / PCAP-NG file");
    }
}

} // namespace pcpp
