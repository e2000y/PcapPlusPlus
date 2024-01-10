#define LOG_MODULE JavaCPPLogModulePCAPFILEIPv4

#include <time.h>
#include <thread>
#include <jni.h>
#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "ProtocolType.h"
#include "PcapFile_IPv4.h"
#include "util.h"

namespace pcpp
{

void processFile(IFileReaderDevice* fileDevice, IPReassembly reassembly, const void* jvm, const std::string& clz, const std::string& mtd, const std::string& sig)
{
    JavaVM* javavm = (JavaVM*) jvm;
    JNIEnv* jenv = nullptr;

    if (javavm->AttachCurrentThread((void **) &jenv, nullptr) == JNI_OK)
    {
        jclass jclz = jenv->FindClass(clz.c_str());

        if (jenv != nullptr)
        {
            if (jclz != nullptr)
            {
                jmethodID jmtd = jenv->GetStaticMethodID(jclz, mtd.c_str(), sig.c_str());

                if (jmtd != nullptr)
                {
                    RawPacket rawPacket = RawPacket();

                    while (fileDevice->getNextPacket(rawPacket))
                    {
                        Packet* pkt = getIPv4Layer(&rawPacket, &reassembly);

                        if (pkt != nullptr)
                        {
                            IPv4Layer* ipLayer = pkt->getLayerOfType<IPv4Layer>(true);

                            if ((ipLayer != nullptr) && (ipLayer->getLayerPayloadSize() > 0) && (ipLayer->getLayerPayload() != nullptr))
                            {
                                timespec t = rawPacket.getPacketTimeStamp();

                                long long time = (t.tv_sec * 1000L) + (t.tv_nsec / 1000000L);
                                jint src =  ipLayer->getIPv4Header()->ipSrc;
                                jint dst = ipLayer->getIPv4Header()->ipDst;
                                jint protocol = ipLayer->getIPv4Header()->protocol;
                                jbyteArray ba = jenv->NewByteArray(ipLayer->getLayerPayloadSize());
                                
                                if (ba != nullptr)
                                {
                                    jenv->SetByteArrayRegion(ba, 0, ipLayer->getLayerPayloadSize(), (jbyte*) ipLayer->getLayerPayload());

                                    jenv->CallStaticVoidMethod(jclz, jmtd, time, src, dst, protocol, ba); 
                                }
                                else
                                {
                                    PCPP_LOG_ERROR("cannot allocate Buffer @" << time << " for size " << ipLayer->getLayerPayloadSize());
                                }
                            }

                            delete pkt;
                        }

                        rawPacket.clear();
                    }

                    PCPP_LOG_INFO("PCAP / PCAP-NG end of file reached");
                }
                else
                {
                    PCPP_LOG_ERROR("cannot find method " << mtd << " - " << sig);
                }
            }
            else
            {
                PCPP_LOG_ERROR("cannot find class " << clz);
            }
        }
        else
        {
            PCPP_LOG_ERROR("cannot get JNIEnv");
        }

        javavm->DetachCurrentThread();
    }
    else
    {
        PCPP_LOG_ERROR("Cannot attach to JVM");
    }
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

void PcapFileInIpV4Out::startProcess(const std::string& bpfFilter, const void* jvm, const std::string& clz, const std::string& mtd, const std::string& sig)
{
	if (m_fileDevice->open())
    {
	    if (!bpfFilter.empty())
	    	m_fileDevice->setFilter(bpfFilter);

        std::thread(&processFile, m_fileDevice, m_reassembly, jvm, clz, mtd, sig).detach();
    }
    else
    {
		PCPP_LOG_ERROR("Cannot open PCAP / PCAP-NG file");
    }
}

} // namespace pcpp
