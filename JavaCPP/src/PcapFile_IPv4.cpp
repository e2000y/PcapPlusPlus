#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "PcapFile_IPv4.h"
#include "util.h"

namespace pcpp
{

PcapFileInIpV4Out::PcapFileInIpV4Out(const std::string& fileName, const bool isNg, const std::string& bpfFilter, size_t maxIPReassembly) :
	reassembly(NULL, NULL, maxIPReassembly)
{
	if (isNg)
	{
		PcapFileReaderDevice device(fileName);

		fileDevice = &device;
	}
	else
	{
		PcapNgFileReaderDevice device(fileName);

		fileDevice = &device;
	}

	if (bpfFilter.empty())
	{
		fileDevice->clearFilter();
	}
	else
	{
		fileDevice->setFilter(bpfFilter);
	}

	if (!fileDevice->open())
		PCPP_LOG_ERROR("Cannot open PCAP / PCAP-NG file '" << fileName << "'");
}

void PcapFileInIpV4Out::stop()
{
	if (fileDevice != NULL)
		fileDevice->close();

	fileDevice = NULL;
}


IPv4Layer* PcapFileInIpV4Out::getNextPacket()
{
	if (fileDevice->isOpened())
	{
		RawPacketVector vec;
		IPv4Layer *ipLayer = NULL;
		bool cont = true;

		while ((ipLayer == NULL) && cont)
		{
			vec.clear();

			fileDevice->getNextPackets(vec, 1);

			if (vec.size() >= 1)
			{
				RawPacket *rp = vec.at(0);

				ipLayer = getIPv4Layer(rp, &reassembly);
			}
			else
			{
				//  cannot read
				cont = false;
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
