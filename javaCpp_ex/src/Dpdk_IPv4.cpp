#define LOG_MODULE JavaCPPLogModuleDPDKIPv4

#include <time.h>
#include <ctime>
#include <stdexcept>
#include <exception>
#include <jni.h>
#include "Logger.h"
#include "RawPacket.h"
#include "Packet.h"
#include "IPv4Layer.h"
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
    uint16_t m_queue;
    IPReassembly* m_reassembly;
    Dpdk_Dev_Rx_Stats* m_stat;
    uint32_t m_mBufPoolSize;
    std::function<void(long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> m_callback;
    std::string m_cbClz;
    std::string m_cbMtd;
    std::string m_cbSig;
    bool m_stop = false;
    uint32_t m_coreId;
    
public:
    AppWorkerThread(uint32_t mBufPoolSize, DpdkDevice* dpdkDev, uint16_t queue, IPReassembly* reassembly, Dpdk_Dev_Rx_Stats* stat, std::function<void(long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> callback)
    {
        m_dpdkDev = dpdkDev;
        m_queue = queue;
        m_reassembly = reassembly;
        m_mBufPoolSize = mBufPoolSize;
        m_callback = callback;

        PCPP_LOG_INFO("AppWorkerThread assigned for DPDK device - " << dpdkDev->getDeviceName() << ", queue: " << queue);
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
            PCPP_LOG_INFO("DPDK device " << m_dpdkDev->getDeviceId() << ":" << m_dpdkDev->getDeviceName() << " use core ID " << coreId);

            MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};
            //  for stats reporting
            int iter = 0;
            std::time_t last = std::time(nullptr);
            DpdkDevice::DpdkDeviceStats theStat;

            while (!m_stop)
            {
                //  we do every 100 iterations - saving CPU
                if ((iter % 100) == 0)
                {
                    std::time_t now = std::time(nullptr);

                    int diff = (int) now - last;

                    //  only report at most 1 minute interval
                    if (diff >= 60)
                    {
                        last = now;

                        m_dpdkDev->getStatistics(theStat);

                        m_stat->tv_sec = (long long) theStat.timestamp.tv_sec;
                        m_stat->rxDrop = theStat.rxPacketsDroppedByHW;
                        m_stat->rxErrs = theStat.rxErroneousPackets;
                        m_stat->rxMbufAllocFail = theStat.rxMbufAlocFailed;
                        m_stat->packets = theStat.aggregatedRxStats.packets;
                        m_stat->bytes = theStat.aggregatedRxStats.bytes;
                        m_stat->packetsPerSec = theStat.aggregatedRxStats.packetsPerSec;
                        m_stat->bytesPerSec = theStat.aggregatedRxStats.bytesPerSec;
                    }

                    iter = 0;
                }

                uint16_t packetsReceived = m_dpdkDev->receivePackets(packetArr, MAX_RECEIVE_BURST, m_queue);

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

                            try
                            {
                                m_callback(time, ipLayer->getIPv4Header()->ipSrc, ipLayer->getIPv4Header()->ipDst, ipLayer->getIPv4Header()->protocol, ipLayer->getLayerPayloadSize(), ipLayer->getLayerPayload());
                            }
                            catch (...)
                            {
                                std::exception_ptr ex = std::current_exception();

                                try
                                {
                                    std::rethrow_exception(ex);
                                }
                                catch (const std::exception& e)
                                {
                                    PCPP_LOG_ERROR("Got exception from JVM - " << e.what());
                                }
                            }
                        }

                        delete pkt;
                    }

                    packetArr[i]->clear();
                }

                iter++;
            }
        }

        PCPP_LOG_INFO("DPDK device " << m_dpdkDev->getDeviceId() << ":" << m_dpdkDev->getDeviceName() << " processing loop end");

        return ret;
    }
};

Dpdk_Ipv4::Dpdk_Ipv4(const std::string& app, const std::vector<std::string>& args, const size_t maxIPReassembly, const uint8_t masterCore, const std::vector<int> svcCores, const uint32_t mBufPoolSizePerDevice, const bool debug) :
	m_reassembly(nullptr, nullptr, maxIPReassembly)
{
    m_coreMask = createCoreMaskFromCoreIds(svcCores);
    m_mBufPoolSizePerDevice = mBufPoolSizePerDevice;

    createCoreVectorFromCoreMask(m_coreMask, m_coresToUse);

    if (m_coresToUse.size() < 1)
    {
        PCPP_LOG_ERROR("Needed minimum of 1 service core");

        throw new std::out_of_range("Needed minimum of 1 service core");
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

    //  for DPDK init
    std::vector<int> nSvcCores = svcCores;
    nSvcCores.push_back((int) masterCore);

    CoreMask coreMask = createCoreMaskFromCoreIds(nSvcCores);

    if (!DpdkDeviceList::initDpdk(coreMask, mBufPoolSizePerDevice, masterCore, cstrings.size(), cstrings.data(), app))
    {
        PCPP_LOG_ERROR("Couldn't initialize DPDK library");

        throw new std::runtime_error("Couldn't initialize DPDK library");
    }
    else
    {
        PCPP_LOG_INFO("DPDK library inited");
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

bool Dpdk_Ipv4::startProcess(const std::vector<std::string> devs, const uint16_t queues, std::function<void(long long, uint32_t, uint32_t, uint8_t, size_t, uint8_t*)> callback)
{
    if (m_coresToUse.size() < devs.size())
    {
        PCPP_LOG_ERROR("Needed at least " << devs.size() << " service cores to process the given device list");

        return false;
    }
    else
    {
        const std::vector<DpdkDevice*> dpdkDevs = DpdkDeviceList::getInstance().getDpdkDeviceList();
        std::vector<DpdkWorkerThread *> workerThreadsVec;

        for (std::string dev : devs)
        {
            DpdkDevice* dpdkDev = DpdkDeviceList::getInstance().getDeviceByPciAddress(dev);

            if (dpdkDev != nullptr)
            {
                dpdkDev->clearStatistics();

                bool ok = true;

                //  open device with # of queues
                if (!dpdkDev->isOpened())
                {
                    ok = dpdkDev->openMultiQueues(queues, 0);
                }

                DpdkDevice::LinkStatus linkSts;

                dpdkDev->getLinkStatus(linkSts);

                if (ok)
                {
                    PCPP_LOG_INFO("Found DPDK device - " << dpdkDev->getDeviceName() << ", link UP: " << linkSts.linkUp << ", Speed: " << linkSts.linkSpeedMbps << ", Duplex: " << linkSts.linkDuplex);

                    Dpdk_Dev_Rx_Stats* devStat = new Dpdk_Dev_Rx_Stats();

                    stats[dpdkDev->getPciAddress()] = devStat;

                    for (uint16_t q = 0; q < dpdkDev->getNumOfOpenedRxQueues(); q++)
                    {
                        workerThreadsVec.push_back(new AppWorkerThread(m_mBufPoolSizePerDevice, dpdkDev, q, &m_reassembly, devStat, callback));
                    }
                }
                else
                {
                    PCPP_LOG_ERROR("cannot open DPDK device - " << dpdkDev->getDeviceName() << ", link UP: " << linkSts.linkUp << ", Speed: " << linkSts.linkSpeedMbps << ", Duplex: " << linkSts.linkDuplex);
                }
            }
            else
            {
                PCPP_LOG_ERROR("Cannot find required DPDK device - " << dev);
            }
        }

        return DpdkDeviceList::getInstance().startDpdkWorkerThreads(m_coreMask, workerThreadsVec);
    }
}

void Dpdk_Ipv4::stopProcess()
{
    DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
}

Dpdk_Dev_Rx_Stats* Dpdk_Ipv4::getDeviceStats(const std::string& dev)
{
    std::map<std::string, Dpdk_Dev_Rx_Stats*>::iterator search = stats.find(dev);

    if (search != stats.end())
    {
        return search->second;
    }
    else
    {
        return nullptr;
    }
}

} // namespace pcpp
