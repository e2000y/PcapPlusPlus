#define LOG_MODULE PacketLogModuleSctpLayer

#include "SctpLayer.h"
#include "IpAddress.h"
#include "PacketUtils.h"
#include "ProtocolType.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#include "EndianPortable.h"

namespace pcpp
{

/// ~~~~~~~~
/// SctpChunk
/// ~~~~~~~~

SctpChunk::SctpChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer)
{
    m_data = data;
    m_dataLen = dataLen;
    m_hdr = hdr;
    m_sctpLayer = sctpLayer;
}

std::list<std::shared_ptr<SctpParam>> SctpChunk::parseSctpParams(uint8_t* data, size_t dataLen) const
{
    size_t totalParamSize = 0;
    uint8_t* ptr = data;
    std::list<std::shared_ptr<SctpParam>> params;
    
    while ((dataLen >= totalParamSize) && ((dataLen - totalParamSize) >= (2 * sizeof(uint16_t)))) {

        std::shared_ptr<SctpParam> param = std::make_shared<SctpParam>(SctpParam(ptr));
        size_t pSize = param->getTotalSize();
        
        totalParamSize += pSize;
        ptr += pSize;
        
        params.push_back(param);
    }

    return params;
}

SctpDataChunk::SctpDataChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_datahdr = (datachunkhdr *) data;
    m_payload = data + sizeof(datachunkhdr);
    m_payloadSize = dataLen - sizeof(datachunkhdr);
}

SctpInitChunk::SctpInitChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_inithdr = (initchunkhdr *) data;
    m_cookieLifeSpanIncrement = 0;
}

void SctpInitChunk::parseChunkData()
{
    std::list<std::shared_ptr<SctpParam>> params = parseSctpParams(m_data + sizeof(initchunkhdr), m_dataLen - sizeof(initchunkhdr));
    
    for (std::shared_ptr<SctpParam> param: params) {
        switch (param->getSctpParamType()) {
            case PCPP_SCTP_INIT_COOKIE_LIFE_INC:
                m_cookieLifeSpanIncrement = be32toh(*reinterpret_cast<uint32_t *>(param->getValue()));
                break;

            case PCPP_SCTP_INIT_IPV4:
                m_ipv4s.push_back(std::make_shared<IPv4Address>(IPv4Address(param->getValue())));
                break;

            case PCPP_SCTP_INIT_IPV6:
                m_ipv6s.push_back(std::make_shared<IPv6Address>(IPv6Address(param->getValue())));
                break;

            case PCPP_SCTP_INIT_HOSTNAME:
            {
                const char *chr = (char *) param->getValue();
                std::string  hostname = std::string(chr, strnlen(chr, param->getDataSize()));
                
                m_hostnames.push_back(std::make_shared<std::string>(hostname));
                break;
            }
                
            case PCPP_SCTP_INIT_ADDR_TYPE:
            {
                uint16_t *types = reinterpret_cast<uint16_t *>(param->getValue());
                size_t num = param->getDataSize() / sizeof(uint16_t);
                
<<<<<<< HEAD
                for (size_t i = 0; i < num; i++) {
=======
                for (int i = 0; i < num; i++) {
>>>>>>> 359050e5 (add SCTP handling;)
                    uint16_t t = be16toh(*(types + i));
                    
                    m_addrTypes.push_back(std::make_shared<uint16_t>(t));
                }
                break;
            }
                
            default:
                ;
        }
    }
    
    //  clear the list after get all data
    params.clear();

}

SctpInitAckChunk::SctpInitAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_initackhdr = (initackchunkhdr *) data;
}

void SctpInitAckChunk::parseChunkData()
{
    std::list<std::shared_ptr<SctpParam>> params = parseSctpParams(m_data + sizeof(initchunkhdr), m_dataLen - sizeof(initchunkhdr));
    
    for (std::shared_ptr<SctpParam> param: params) {
        switch (param->getSctpParamType()) {
            case PCPP_SCTP_INIT_IPV4:
                m_ipv4s.push_back(std::make_shared<IPv4Address>(IPv4Address(param->getValue())));
                break;
                
            case PCPP_SCTP_INIT_IPV6:
                m_ipv6s.push_back(std::make_shared<IPv6Address>(IPv6Address(param->getValue())));
                break;
                
            case PCPP_SCTP_INIT_HOSTNAME:
            {
                const char *chr = (char *) param->getValue();
                std::string  hostname = std::string(chr, strnlen(chr, param->getDataSize()));
                
                m_hostnames.push_back(std::make_shared<std::string>(hostname));
                break;
            }
                
            case PCPP_SCTP_INIT_ACK_COOKIE:
                m_cookieData = param->getValue();
                m_cookieSize = param->getDataSize();
                break;

            case PCPP_SCTP_ERR_INV_PARAM:
                m_unrecognizedParameters = parseSctpParams(param->getValue(), param->getDataSize());
                break;
                
            default:
                ;
        }
    }
    
    //  clear the list after get all data
    params.clear();

}

SctpSAckChunk::SctpSAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_sackhdr = (sackchunkhdr *) data;
    m_gapBlocks = (sackgapblock *) (data + sizeof(sackchunkhdr));
    m_dupTsns = (uint32_t *) (m_gapBlocks + (sizeof(sackgapblock) * getGapBlockCount()));
}

SctpHbChunk::SctpHbChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }
   
void SctpHbChunk::parseChunkData()
{
    std::list<std::shared_ptr<SctpParam>> params = parseSctpParams(m_data, m_dataLen);
    
    for (std::shared_ptr<SctpParam> param: params) {
        switch (param->getSctpParamType()) {
            case PCPP_SCTP_HB_INFO:
                m_hbInfo = param->getValue();
                m_hbInfoSize = param->getDataSize();
                break;
                
            default:
                ;
        }
    }
    
    //  clear the list after get all data
    params.clear();
    
}

SctpHbAckChunk::SctpHbAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpHbChunk(data, dataLen, hdr, sctpLayer)
{ }

SctpAbortChunk::SctpAbortChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }

void SctpAbortChunk::parseChunkData()
{
    m_errors = parseSctpParams(m_data, m_dataLen);
}

SctpShutdownChunk::SctpShutdownChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_cumulativeTsnAck = be32toh(*reinterpret_cast<uint32_t *>(data));
}

SctpShutdownAckChunk::SctpShutdownAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }

SctpErrorChunk::SctpErrorChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }

void SctpErrorChunk::parseChunkData()
{
    m_errors = parseSctpParams(m_data, m_dataLen);
}

SctpCookieEchoChunk::SctpCookieEchoChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{
    m_cookie = data;
    m_cookieSize = dataLen;
}

SctpCookieAckChunk::SctpCookieAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }

SctpShutdownCompChunk::SctpShutdownCompChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer) : SctpChunk(data, dataLen, hdr, sctpLayer)
{ }


/// ~~~~~~~~
/// SctpLayer
/// ~~~~~~~~

uint16_t SctpLayer::getSrcPort() const
{
	return be16toh(getSctpHeader()->portSrc);
}

uint16_t SctpLayer::getDstPort() const
{
	return be16toh(getSctpHeader()->portDst);
}

uint32_t SctpLayer::getVerficationTag() const
{
    return be32toh(getSctpHeader()->verficationTag);
}

uint32_t SctpLayer::getChecksum() const
{
    return be32toh(getSctpHeader()->checksum);
}

SctpLayer::SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = SCTP;
    
    //   extract chunks
    size_t totalChunkSize = sizeof(sctphdr);
    uint8_t* ptr = data + sizeof(sctphdr);
    
    //  at least can read the common chunk header
    while ((dataLen >= totalChunkSize) && ((dataLen - totalChunkSize) >= sizeof(commonchunkhdr))) {

        commonchunkhdr* ccHdr = (commonchunkhdr *) ptr;

        uint8_t* cPtr = ptr + sizeof(commonchunkhdr);
        size_t cTotalLen = be16toh(ccHdr->len);
        
        if (cTotalLen >= sizeof(commonchunkhdr)) {
            
            size_t cLen = cTotalLen - sizeof(commonchunkhdr);

            switch (*ptr & 0x3f) {
                case PCPP_SCTP_DATA:
                {
                    std::shared_ptr<SctpDataChunk> data = std::make_shared<SctpDataChunk>(SctpDataChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(data);
                    break;
                }
                    
                case PCPP_SCTP_INIT:
                {
                    std::shared_ptr<SctpInitChunk> init = std::make_shared<SctpInitChunk>(SctpInitChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(init);
                    break;
                }
                    
                case PCPP_SCTP_INIT_ACK:
                {
                    std::shared_ptr<SctpInitAckChunk> initAck = std::make_shared<SctpInitAckChunk>(SctpInitAckChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(initAck);
                    break;
                }
                    
                case PCPP_SCTP_SACK:
                {
                    std::shared_ptr<SctpSAckChunk> sack = std::make_shared<SctpSAckChunk>(SctpSAckChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(sack);
                    break;
                }
                    
                case PCPP_SCTP_HEARTBEAT:
                {
                    std::shared_ptr<SctpHbChunk> hb = std::make_shared<SctpHbChunk>(SctpHbChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(hb);
                    break;
                }
                    
                case PCPP_SCTP_HEARTBEAT_ACK:
                {
                    std::shared_ptr<SctpHbAckChunk> hbAck = std::make_shared<SctpHbAckChunk>(SctpHbAckChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(hbAck);
                    break;
                }
                    
                case PCPP_SCTP_ABORT:
                {
                    std::shared_ptr<SctpAbortChunk> abort = std::make_shared<SctpAbortChunk>(SctpAbortChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(abort);
                    break;
                }
                    
                case PCPP_SCTP_SHUTDOWN:
                {
                    std::shared_ptr<SctpShutdownChunk> shutdown = std::make_shared<SctpShutdownChunk>(SctpShutdownChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(shutdown);
                    break;
                }
                    
                case PCPP_SCTP_SHUTDOWN_ACK:
                {
                    std::shared_ptr<SctpShutdownAckChunk> shutdownAck = std::make_shared<SctpShutdownAckChunk>(SctpShutdownAckChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(shutdownAck);
                    break;
                }
                    
                case PCPP_SCTP_ERROR:
                {
                    std::shared_ptr<SctpErrorChunk> error = std::make_shared<SctpErrorChunk>(SctpErrorChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(error);
                    break;
                }
                    
                case PCPP_SCTP_COOKIE_ECHO:
                {
                    std::shared_ptr<SctpCookieEchoChunk> cookie = std::make_shared<SctpCookieEchoChunk>(SctpCookieEchoChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(cookie);
                    break;
                }
                    
                case PCPP_SCTP_COOKIE_ACK:
                {
                    std::shared_ptr<SctpCookieAckChunk> cookieAck = std::make_shared<SctpCookieAckChunk>(SctpCookieAckChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(cookieAck);
                    break;
                }
                    
                case PCPP_SCTP_SHUTDOWN_COMPLETE:
                {
                    std::shared_ptr<SctpShutdownCompChunk> shutdownComp = std::make_shared<SctpShutdownCompChunk>(SctpShutdownCompChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(shutdownComp);
                    break;
                }
                    
                default:
                {
                    std::shared_ptr<SctpChunk> chunk = std::make_shared<SctpChunk>(SctpChunk(cPtr, cLen, ccHdr, this));
                    m_sctpChunks.push_back(chunk);
                }
            }
            
        } else {
            //  chunk length error - skip the whole packet
            break;
        }
        
	size_t sz = m_sctpChunks.back()->getChunkSizeWithPad();

	totalChunkSize += sz;
	ptr += sz;
        
    }

}

std::string SctpLayer::toString() const
{
    sctphdr* hdr = getSctpHeader();
	std::string result = "SCTP Layer, ";
    
	std::ostringstream srcPortStream;
	srcPortStream << getSrcPort();
	std::ostringstream dstPortStream;
	dstPortStream << getDstPort();
    std::ostringstream vTagStream;
    vTagStream << hdr->verficationTag;
    
	result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str() + ", Verfication Tag: " + vTagStream.str();

    //  dump the chunk types
    std::ostringstream chunkStream;
    
    for (std::shared_ptr<SctpChunk> chunk: m_sctpChunks) {
        int ct = chunk->getChunkType();

        chunkStream << " [ " << ct << " , " << chunk->getChunkSize() << " , " << chunk->getChunkSizeWithPad() << " ] ";
        
        chunk->parseChunkData();
    }
    
    result += ", Chunks: " + chunkStream.str();
    
	return result;
}

} // namespace pcpp
