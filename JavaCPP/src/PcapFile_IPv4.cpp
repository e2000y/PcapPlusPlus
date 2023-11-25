#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

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
            IPv4Layer* ipLayer = pkt->getLayerOfType<pcpp::IPv4Layer>(true);

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

    PCPP_LOG_ERROR("PCAP / PCAP-NG end of file reached");

    callback(true, 0L, NULL);
}

PcapFileInIpV4Out::PcapFileInIpV4Out(const std::string& fileName, const bool isNg, size_t maxIPReassembly) :
	reassembly(NULL, NULL, maxIPReassembly)
{
	if (isNg)
		fileDevice = new PcapNgFileReaderDevice(fileName);
	else
		fileDevice = new PcapFileReaderDevice(fileName);
}

PcapFileInIpV4Out::~PcapFileInIpV4Out()
{
    if (fileDevice != NULL)
    {
        fileDevice->close();

        delete fileDevice;

        fileDevice = NULL;
    }
}

void PcapFileInIpV4Out::startProcess(const std::string& bpfFilter, void (*callback)(bool isEnd, long long time, IPv4Layer* layer))
{
	if (fileDevice->open())
    {
	    if (!bpfFilter.empty())
	    	fileDevice->setFilter(bpfFilter);

        std::thread(&processFile, fileDevice, reassembly, callback).detach();
    }
    else
    {
		PCPP_LOG_ERROR("Cannot open PCAP / PCAP-NG file");
    }
}

} // namespace pcpp
