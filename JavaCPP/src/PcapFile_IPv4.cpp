#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "PcapFile_IPv4.h"
#include "util.h"

namespace pcpp
{

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

bool PcapFileInIpV4Out::start(const std::string& bpfFilter)
{
	if (!fileDevice->open())
    {
		PCPP_LOG_ERROR("Cannot open PCAP / PCAP-NG file");

        return false;
    }
    else
    {
	    if (!bpfFilter.empty())
	    	fileDevice->setFilter(bpfFilter);

        return true;
    }
}

IPv4Layer* PcapFileInIpV4Out::getNextPacket()
{
	if (fileDevice->isOpened())
	{
		IPv4Layer *ipLayer = NULL;
		bool cont = true;

		while ((ipLayer == NULL) && cont)
		{
            RawPacket* newPacket = new RawPacket();

            if (fileDevice->getNextPacket(*newPacket))
            {
				ipLayer = getIPv4Layer(newPacket, &reassembly);
            }
            else
            {
				//  cannot read anymore
				cont = false;

                PCPP_LOG_ERROR("NO more records can be read");
            }
		}

		return ipLayer;
	}
	else 
	{
		PCPP_LOG_ERROR("PCAP / PCAP-NG file not opened");

		return NULL;
	}

}

} // namespace pcpp
