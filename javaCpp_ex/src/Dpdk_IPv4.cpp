#define LOG_MODULE JavaCPPLogModuleDPDKIPv4

#include <time.h>
#include <stdexcept>
#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "Dpdk_IPv4.h"
#include "util.h"

namespace pcpp
{

#define MAX_RECEIVE_BURST 256

class AppWorkerThread : public DpdkWorkerThread
{
private:
    DpdkDevice* m_dpdkDev;
    IPReassembly* m_reassembly;
    uint32_t m_mBufPoolSize;
    void (*m_callback)(bool isEnd, long long time, IPv4Layer* layer);
    bool m_stop = false;
    uint32_t m_coreId;
    
public:
    AppWorkerThread(uint32_t mBufPoolSize, DpdkDevice* dpdkDev, IPReassembly* reassembly, void (*callback)(bool isEnd, long long time, IPv4Layer* layer))
    {
        m_dpdkDev = dpdkDev;
        m_reassembly = reassembly;
        m_mBufPoolSize = mBufPoolSize;
        m_callback = callback;
    }

    ~AppWorkerThread()
    { }

    void stop()
    {
        m_stop = true;
    }

    uint32_t getCoreId() const
    {
        return m_coreId;
    }

    bool run(uint32_t coreId)
    {
        m_stop = false;
        m_coreId = coreId;

        bool ret = true;

        if (m_dpdkDev == nullptr)
        {
            PCPP_LOG_ERROR("NO DPDK device assigned to core - " << coreId);

            ret = false;
        }
        else
        {
            const uint16_t queues = m_dpdkDev->getNumOfOpenedRxQueues();
            MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};

            while (!m_stop)
            {
                uint16_t errors = 0;

                for (uint16_t q = 0; q < queues; q++)
                {
                    uint16_t packetsReceived = m_dpdkDev->receivePackets(packetArr, MAX_RECEIVE_BURST, q);

                    if (packetsReceived == 0)
                    {
                        PCPP_LOG_ERROR("Cannot get packet from " << m_dpdkDev->getDeviceId() << ":" << m_dpdkDev->getDeviceName() << ", queue: " << q);

                        errors++;
                    }
                    else
                    {
                        for (int i = 0; i < packetsReceived; i++)
                        {
                            //  parse packet
                            Packet* pkt = getIPv4Layer(packetArr[i], m_reassembly);

                            if (pkt != nullptr)
                            {
                                IPv4Layer* ipLayer = pkt->getLayerOfType<pcpp::IPv4Layer>(true);

                                if (ipLayer != nullptr)
                                {
                                    timespec t = packetArr[i]->getPacketTimeStamp();

                                    long long time = (t.tv_sec * 1000L) + (t.tv_nsec / 1000000L);

                                    m_callback(false, time, ipLayer);
                                }

                                delete pkt;
                            }

                            packetArr[i]->clear();
                        }
                    }
                }

                if (errors == queues)
                {
                    m_stop = true;

                    PCPP_LOG_ERROR("Cannot get packet for all queues from " << m_dpdkDev->getDeviceId() << ":" << m_dpdkDev->getDeviceName() << ", break");

                    ret = false;
                }
            }
        }

        PCPP_LOG_INFO("DPDK device " << m_dpdkDev->getDeviceId() << ":" << m_dpdkDev->getDeviceName() << " processing loop end");

        m_callback(true, 0L, nullptr);

        return ret;
    }
};

Dpdk_Ipv4::Dpdk_Ipv4(const std::string& app, const std::vector<std::string>& args, const size_t maxIPReassembly, const uint8_t masterCore, const CoreMask coreMask, const uint32_t mBufPoolSizePerDevice, const bool debug) :
	m_reassembly(nullptr, nullptr, maxIPReassembly)
{
    m_coreMask = coreMask;
    m_mBufPoolSizePerDevice = mBufPoolSizePerDevice;

    createCoreVectorFromCoreMask(coreMask, m_coresToUse);

    if (m_coresToUse.size() < 2)
    {
        PCPP_LOG_ERROR("Needed minimum of 2 cores");

        throw new std::out_of_range("Needed minimum of 2 cores");
    }

    if ((coreMask & DpdkDeviceList::getInstance().getDpdkMasterCore().Mask) != 0)
    {
        PCPP_LOG_ERROR("coreMask cannot include master core");

        throw new std::range_error("coreMask cannot include master core");
    }

    //  convert string array to **char
    std::vector<std::vector<char>> vstrings;
    std::vector<char*> cstrings;

    vstrings.reserve(args.size());
    cstrings.reserve(args.size());

    for (size_t i = 0; i < args.size(); ++i)
    {
        vstrings.emplace_back(args[i].begin(), args[i].end());
        vstrings.back().push_back('\0');
        cstrings.push_back(vstrings.back().data());
    }

    if (!DpdkDeviceList::getInstance().initDpdk(coreMask, mBufPoolSizePerDevice, masterCore, cstrings.size(), cstrings.data(), app))
    {
        PCPP_LOG_ERROR("Couldn't initialize DPDK");

        throw new std::runtime_error("Couldn't initialize DPDK");
    }

    const std::vector<DpdkDevice*> devs = DpdkDeviceList::getInstance().getDpdkDeviceList();

    for (DpdkDevice* dev : devs)
    {
        PCPP_LOG_INFO("Find DPDK device - " << dev->getDeviceName() << ": [" << dev->getDeviceId() << "], " << dev->getPciAddress() << " , " << dev->getPMDName() << ", " << dev->getPMDType());
    }

    if (debug)
    {
        DpdkDeviceList::getInstance().setDpdkLogLevel(Logger::Debug);
    }
    else
    {
        DpdkDeviceList::getInstance().setDpdkLogLevel(Logger::Info);
    }
}

Dpdk_Ipv4::~Dpdk_Ipv4()
{
    DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
}

bool Dpdk_Ipv4::startProcess(const std::vector<std::string> devs, void (*callback)(bool isEnd, long long time, IPv4Layer* layer))
{
    if (m_coresToUse.size() < devs.size())
    {
        PCPP_LOG_ERROR("Needed at least " << devs.size() << " cores to process the given devices");

        return false;
    }
    else
    {
        const std::vector<DpdkDevice*> dpdkDevs = DpdkDeviceList::getInstance().getDpdkDeviceList();
        std::vector<DpdkWorkerThread *> workerThreadsVec;

        for (DpdkDevice* dpdkDev : dpdkDevs)
        {
            if (std::find(std::begin(devs), std::end(devs), dpdkDev->getPciAddress()) != std::end(devs))
            {
                workerThreadsVec.push_back(new AppWorkerThread(m_mBufPoolSizePerDevice, dpdkDev, &m_reassembly, callback));
            }
            else
            {
                PCPP_LOG_ERROR("Cannot find required DPDK device - " << dpdkDev->getDeviceName());
            }
        }

        return DpdkDeviceList::getInstance().startDpdkWorkerThreads(m_coreMask, workerThreadsVec);
    }
}

void Dpdk_Ipv4::stopProcess()
{
    DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
}

} // namespace pcpp
