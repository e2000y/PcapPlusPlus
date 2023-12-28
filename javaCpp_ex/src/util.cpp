
#include "util.h"

/**
 * @return the last IPv4 Layer after re-assembly the raw packet
 */
pcpp::Packet* getIPv4Layer(pcpp::RawPacket *rp, pcpp::IPReassembly *reassembly)
{
	pcpp::Packet* packet = new pcpp::Packet(rp, false, pcpp::UnknownProtocol, pcpp::OsiModelSesionLayer);
	pcpp::IPReassembly::ReassemblyStatus sts;

	pcpp::Packet *output = reassembly->processPacket(packet, sts, pcpp::UnknownProtocol, pcpp::OsiModelSesionLayer);

    if (packet != output)
    {
        delete packet;
    }

	if ((sts == pcpp::IPReassembly::REASSEMBLED) || (sts == pcpp::IPReassembly::NON_FRAGMENT))
	{
		return output;
	}
	else
		return nullptr;
}

