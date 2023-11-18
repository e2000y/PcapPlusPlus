
#include "util.h"

pcpp::IPv4Layer* getIPv4Layer(pcpp::RawPacket *rp, pcpp::IPReassembly *reassembly)
{
	pcpp::Packet packet(rp, true, pcpp::IPv4, pcpp::OsiModelNetworkLayer);
	pcpp::IPReassembly::ReassemblyStatus sts;

	pcpp::Packet *output = reassembly->processPacket(&packet, sts, pcpp::IPv4, pcpp::OsiModelNetworkLayer);

	if ((sts == pcpp::IPReassembly::REASSEMBLED) || (sts == pcpp::IPReassembly::NON_FRAGMENT))
	{
		pcpp::IPv4Layer *ipv4 = dynamic_cast<pcpp::IPv4Layer*>(output->getLayerOfType(pcpp::IPv4, 0));

		return ipv4;
	}
	else
		return NULL;
}

