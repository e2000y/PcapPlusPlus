#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

#include <time.h>
#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "PcapFile_IPv4.h"
#include "util.h"

namespace pcpp
{

void processFile(IFileReaderDevice* fileDevice, IPReassembly reassembly, void (*callback)(bool isEnd, long long time, IPv4Layer* layer))
{
    RawPacket rawPacket = RawPacket();

    while (fileDevice->getNextPacket(rawPacket))
    {
        Packet* pkt = getIPv4Layer(&rawPacket, &reassembly);

        if (pkt != NULL)
        {
            IPv4Layer* ipLayer = pkt->getLayerOfType<IPv4Layer>(true);

            if (ipLayer != NULL)
            {
                timespec t = rawPacket.getPacketTimeStamp();

                long long time = (t.tv_sec * 1000L) + (t.tv_nsec / 1000000L);

                callback(false, time, ipLayer);
            }

            delete pkt;
        }

        rawPacket.clear();
    }

    PCPP_LOG_INFO("PCAP / PCAP-NG end of file reached");

    callback(true, 0L, NULL);
}

PcapFileInIpV4Out::PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly) :
	m_reassembly(NULL, NULL, maxIPReassembly)
{
	if (isNg)
		m_fileDevice = new PcapNgFileReaderDevice(fileName);
	else
		m_fileDevice = new PcapFileReaderDevice(fileName);
}

PcapFileInIpV4Out::~PcapFileInIpV4Out()
{
    if (m_fileDevice != NULL)
    {
        m_fileDevice->close();

        delete m_fileDevice;

        m_fileDevice = NULL;
    }
}

void PcapFileInIpV4Out::startProcess(const std::string& bpfFilter, void (*callback)(bool isEnd, long long time, IPv4Layer* layer))
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
