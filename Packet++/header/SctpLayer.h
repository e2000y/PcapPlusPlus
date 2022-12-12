#pragma once

#include "Layer.h"
#include "TLVData.h"
#include <string.h>
#include <list>
#include <memory>
#include "EndianPortable.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct sctphdr
	 * Represents an SCTP protocol header
	 */
#pragma pack(push,1)

	struct sctphdr
	{
		/** Source SCTP port */
		uint16_t portSrc;
		/** Destination SCTP port */
		uint16_t portDst;
		/** Verification Tag */
		uint32_t verficationTag;
		/** Checksum */
		uint32_t checksum;
	};

	/**
	 * generic chunk
	 */
	struct commonchunkhdr
	{
		/** Chunk Type */
		uint8_t chunkType;
		/** Flag */
		uint8_t flag;
		/** Chunk length */
		uint16_t len;
	};

	/**
	 * data chunk
	 */
	struct datachunkhdr
	{
		/** TSN */
		uint32_t tsn;
		/** stream ID */
		uint16_t streamId;
		/** stream seq */
		uint16_t streamSeq;
		/** PPI */
		uint32_t ppi;
	};

	/**
	 * init chunk
	 */
	struct initchunkhdr
	{
		/** Initiate tag */
		uint32_t initTag;
		/** Advertised receiver window credit */
		uint32_t a_rwnd;
		/** # of outbound streams */
		uint16_t outbound;
		/** # of inbound streams */
		uint16_t inbound;
		/** Initiate TSN */
		uint32_t initTsn;
	};

	/**
	 * init ack chunk
	 */
	struct initackchunkhdr
	{
		/** Initiate tag */
		uint32_t initTag;
		/** Advertised receiver window credit */
		uint32_t a_rwnd;
		/** # of outbound streams */
		uint16_t outbound;
		/** # of inbound streams */
		uint16_t inbound;
		/** Initiate TSN */
		uint32_t initTsn;
	};

	struct sackchunkhdr
	{
		/** Cumulative tag */
		uint32_t cumulativeTag;
		/** Advertised receiver window credit */
		uint32_t a_rwnd;
		/** Number of Gap Ack Blocks */
		uint16_t gapAck;
		/** Number of Duplicate TSNs */
		uint16_t dupTsn;
	};

    struct sackgapblock
    {
        uint16_t start;
        uint16_t end;
    };

#pragma pack(pop)

/** IPv4 address */
#define PCPP_SCTP_INIT_IPV4               5
/** IPv6 address */
#define PCPP_SCTP_INIT_IPV6               6
/** Suggested cookie life-span increment */
#define PCPP_SCTP_INIT_COOKIE_LIFE_INC    9
/** Hostname */
#define PCPP_SCTP_INIT_HOSTNAME           11
/** address type */
#define PCPP_SCTP_INIT_ADDR_TYPE          12

/** state cookie */
#define PCPP_SCTP_INIT_ACK_COOKIE         7
/** unrecognized parameter */
#define PCPP_SCTP_ERR_INV_PARAM           8


/** heartbeat info */
#define PCPP_SCTP_HB_INFO                 1

/** invalid stream identifier */
#define PCPP_SCTP_ERR_INV_STREAM_ID       1
/** missing mandatory parameters */
#define PCPP_SCTP_ERR_MISS_PARAM          2
/** stale cookie */
#define PCPP_SCTP_ERR_STALE_COOKIE        3
/** out of resources */
#define PCPP_SCTP_ERR_OUT_OF_RES          4
/** address that could not resolve */
#define PCPP_SCTP_ERR_INV_ADDR            5
/** unrecognized chunk type */
#define PCPP_SCTP_ERR_INV_CHUNK_TYPE      6
/** invalid value */
#define PCPP_SCTP_ERR_INV_VALUE           7
/** unrecognized parameter */
#define PCPP_SCTP_ERR_INV_PARAM           8
/** no user data */
#define PCPP_SCTP_ERR_NO_DATA             9
/** received a COOKIE ECHO while the endpoint was in a SHUTDOWN-ACK-SENT state */
#define PCPP_SCTP_ERR_INV_STATE           10
/** Restart of an Association with New Addresses */
#define PCPP_SCTP_ERR_RESTART             11
/** User Initiated Abort */
#define PCPP_SCTP_ERR_USER_ABORT          12
/** Protocol Violation */
#define PCPP_SCTP_ERR_PROTOCOL_VIOLATION  13

/** Data */
#define PCPP_SCTP_DATA                    0
/** Init */
#define PCPP_SCTP_INIT                    1
/** Init Ack */
#define PCPP_SCTP_INIT_ACK                2
/** SACK */
#define PCPP_SCTP_SACK                    3
/** HEARTBEAT */
#define PCPP_SCTP_HEARTBEAT               4
/** HEARTBEAT ACK */
#define PCPP_SCTP_HEARTBEAT_ACK           5
/** ABORT */
#define PCPP_SCTP_ABORT                   6
/** SHUTDOWN */
#define PCPP_SCTP_SHUTDOWN                7
/** SHUTDOWN ACK */
#define PCPP_SCTP_SHUTDOWN_ACK            8
/** ERROR */
#define PCPP_SCTP_ERROR                   9
/** COOKIE ECHO */
#define PCPP_SCTP_COOKIE_ECHO             10
/** COOKIE ACK */
#define PCPP_SCTP_COOKIE_ACK              11
/** SHUTDOWN COMPLETE */
#define PCPP_SCTP_SHUTDOWN_COMPLETE       14

//  no supported yet - will be generic SctpChunk

/** ECNE */
#define PCPP_SCTP_ECNE                    12
/** CWR */
#define PCPP_SCTP_CWR                     13
/** AUTH */
#define PCPP_SCTP_AUTH                    15

	/**
	 * @class SctpParam
	 * A wrapper class for SCTP chunk header parameters.
	 */
	class SctpParam : public TLVRecord<uint16_t, uint16_t>
	{
	public:

		/**
		 * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
		 */
		SctpParam(uint8_t* optionRawData) : TLVRecord(optionRawData) { }

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~SctpParam() { }

		/**
		 * @return the parameter type
		 */
		uint16_t getSctpParamType() const
		{
			if (m_Data == NULL)
				return 65535;

			return be16toh(m_Data->recordType);
		}

        /**
         * @return the wire size - pad to 4 bytes alignment
         */
		size_t getTotalSize() const
		{
			if (m_Data == NULL)
				return (size_t) 0;
			else
			{
				// aligned to 4 bytes boundary
                size_t len =  (size_t) be16toh(m_Data->recordLen);
				size_t mod4 = len % 4;

				if (mod4 > 0)
				{
                    size_t div4 = len / 4;

					return (div4 + 1) * 4;
				}
				else
                    return len;
			}

		}

        /**
         * @return the parameter size
         */
		size_t getDataSize() const
		{
			if (m_Data == NULL)
                return (size_t) 0;

			return (size_t) be16toh(m_Data->recordLen) - (2 * sizeof(uint16_t));
		}
    };

    //  forward declaration
    class SctpLayer;

    /**
     * @class SctpChunk
     * A wrapper class for SCTP generic chunk.
     */
	class SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         * @param[in] data A pointer to the raw data after the chunk common header
         * @param[in] dataLen Size of the data in bytes
         * @param[in] hdr a pointer to the common SCTP chunk header
         * @param[in] sctpLayer A pointer to the SCTP layer
         */
		SctpChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
        virtual ~SctpChunk() {}

        /**
         * @return the action bits of SCTP chunk type
         */
		uint8_t getChunkAction()
		{
			if (m_hdr == NULL)
				return 0;
			else
				return (m_hdr->chunkType >> 6) & 0x03;
		}

        /**
         * @return the SCTP chunk type
         */
		uint8_t getChunkType()
		{
			if (m_hdr == NULL)
				return 0;
			else
				return (m_hdr->chunkType) & 0x3f;
		}
        
        uint8_t getFlags()
        {
            if (m_hdr == NULL)
                return 0;
            else
                return m_hdr->flag;
        }
        
        /**
         * @return the SCTP chunk size
         */
		size_t getChunkSize()
		{
			if (m_hdr == NULL)
				return 0;
			else
				return (size_t) be16toh(m_hdr->len);
		}

        /**
         * @return the SCTP chunk size with pad to 4 bytes alignment
         */
		size_t getChunkSizeWithPad()
		{
			if (m_hdr == NULL)
				return 0;
			else
			{
				// aligned to 4 bytes boundary
                size_t len = be16toh(m_hdr->len);
				size_t mod4 = len % 4;

				if (mod4 > 0)
				{
					size_t div4 = len / 4;

					return (div4 + 1) * 4;
				}
				else
					return len;
			}
		}

        SctpLayer* getSctpLayer()
        {
            return m_sctpLayer;
        }
        
        /**
         * @return the pointer to the SCTP chunk value after the chunk header
         */
		uint8_t* getData()
		{
			return m_data;
		}

        /**
         * @return the SCTP chunk size after the chunk header
         */
		size_t getDataLen()
		{
			return m_dataLen;
		}

        /**
         * parse the chunk data to get detail so the constructor will run faster
         * before the chunk data parsed, no optional parameters are available
         */
        virtual void parseChunkData() {}
        
    protected:
        /**
         * parse the data to get the list of SCTP chunk optional parameters
         * @param[in] data A pointer to the start of optional parameters data
         * @param[in] dataLen Size of the data in bytes
         */
        std::list<std::shared_ptr<SctpParam>> parseSctpParams(uint8_t* data, size_t dataLen) const;

        uint8_t* m_data;
        size_t m_dataLen;
        commonchunkhdr *m_hdr;
        SctpLayer *m_sctpLayer;
    };

    /**
     * @class SctpDataChunk
     * A wrapper class for SCTP DATA chunk.
     */
	class SctpDataChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpDataChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpDataChunk() {}

        /**
         * @return is the end of SCTP data chunk fragment
         */
		bool isEndFragment()
		{
			if (m_hdr == NULL)
				return true;
			else
				return m_hdr->flag & 0x01;
		}

        /**
         * @return is the begin of SCTP data chunk fragment
         */
		bool isBeginFragment()
		{
			if (m_hdr == NULL)
				return true;
			else
				return m_hdr->flag & 0x02;
		}

        /**
         * @return is the unordered SCTP data chunk
         */
		bool isUnorder()
		{
			if (m_hdr == NULL)
				return true;
			else
				return m_hdr->flag & 0x04;
		}

        /**
         * @return is the data chunk required immediate SACK
         */
		bool isImmediate()
		{
			if (m_hdr == NULL)
				return true;
			else
				return m_hdr->flag & 0x08;
		}

        /**
         * @return true if it is the 1st fragment
         */
        bool isFirstFragment()
        {
            return isBeginFragment() && !isEndFragment();
        }

        /**
         * @return true if it is the 1st fragment
         */
        bool isPartOfFragment()
        {
            return !(isBeginFragment() || isEndFragment());
        }

        /**
         * @return true if it is the last fragment
         */
        bool isLastFragment()
        {
            return !isBeginFragment() && isEndFragment();
        }

        /**
         * @return true if it is the unfragment
         */
        bool isUnFragment()
        {
            return isBeginFragment() && isEndFragment();
        }

        /**
         * @return the TSN
         */
		uint32_t getTSN()
		{
			if (m_datahdr == NULL)
				return 0;
			else
				return be32toh(m_datahdr->tsn);
		}

        /**
         * @return the stream ID
         */
		uint16_t getStreamID()
		{
			if (m_datahdr == NULL)
				return 0;
			else
				return be16toh(m_datahdr->streamId);
		}

        /**
         * @return the stream sequence
         */
		uint16_t getStreamSeq()
		{
			if (m_datahdr == NULL)
				return 0;
			else
				return be16toh(m_datahdr->streamSeq);
		}

        /**
         * @return the payload protocol identifier
         */
		uint32_t getPPI()
		{
			if (m_datahdr == NULL)
				return 0;
			else
				return be32toh(m_datahdr->ppi);
		}

        /**
         * @return the pointer to payload data
         */
		uint8_t* getPayload()
		{
			return m_payload;
		}

        /**
         * @return the payload data size
         */
		size_t getPayloadSize()
		{
			return m_payloadSize;
		}

	private:
		datachunkhdr *m_datahdr;
		uint8_t *m_payload;
		size_t m_payloadSize;

    };

    /**
     * @class SctpInitChunk
     * A wrapper class for SCTP INIT chunk.
     */
	class SctpInitChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpInitChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpInitChunk()
        {
            m_ipv4s.clear();
            m_ipv6s.clear();
            m_hostnames.clear();
            m_addrTypes.clear();
        }

        /**
         * @return the initial tag
         */
		uint32_t getInitiateTag()
		{
			if (m_inithdr == NULL)
				return 0;
			else
				return be32toh(m_inithdr->initTag);
		}

        /**
         * @return the Advertised Receiver Window
         */
		uint32_t getA_rwnd()
		{
			if (m_inithdr == NULL)
				return 0;
			else
				return be32toh(m_inithdr->a_rwnd);
		}

        /**
         * @return the outbound stream count
         */
		uint16_t getOutboundStream()
		{
			if (m_inithdr == NULL)
				return 0;
			else
				return be16toh(m_inithdr->outbound);
		}

        /**
         * @return the inbound stream count
         */
		uint16_t getInboundStream()
		{
			if (m_inithdr == NULL)
				return 0;
			else
				return be16toh(m_inithdr->inbound);
		}

        /**
         * @return the initial TSN
         */
		uint32_t getInitiateTSN()
		{
			if (m_inithdr == NULL)
				return 0;
			else
				return be32toh(m_inithdr->initTsn);
		}

        /**
         * @return the cookie life span increment
         */
		uint32_t getCookieLifeSpanIncrement()
		{
			return m_cookieLifeSpanIncrement;
		}

        /**
         * @return the list of IPv4 addresses
         */
		std::list<std::shared_ptr<IPv4Address>> getIPv4Addresses()
		{
			return m_ipv4s;
		}

        /**
         * @return the list of IPv6 addresses
         */
		std::list<std::shared_ptr<IPv6Address>> getIPv6Addresses()
		{
			return m_ipv6s;
		}

        /**
         * @return the list of HostNames
         */
		std::list<std::shared_ptr<std::string>> getHostNames()
		{
			return m_hostnames;
		}

        /**
         * @return the list of supported address types
         */
		std::list<std::shared_ptr<uint16_t>> getSupportedAddressTypes()
		{
			return m_addrTypes;
		}

        virtual void parseChunkData();

	private:
		initchunkhdr *m_inithdr;
        
		uint32_t m_cookieLifeSpanIncrement;
		std::list<std::shared_ptr<IPv4Address>> m_ipv4s;
		std::list<std::shared_ptr<IPv6Address>> m_ipv6s;
		std::list<std::shared_ptr<std::string>> m_hostnames;
		std::list<std::shared_ptr<uint16_t>> m_addrTypes;

    };

    /**
     * @class SctpInitAckChunk
     * A wrapper class for SCTP INIT ACK chunk.
     */
	class SctpInitAckChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpInitAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpInitAckChunk()
        {
            m_ipv4s.clear();
            m_ipv6s.clear();
            m_hostnames.clear();
            m_unrecognizedParameters.clear();
        }

        /**
         * @return the initial tag
         */
		uint32_t getInitiateTag()
		{
			if (m_initackhdr == NULL)
				return 0;
			else
				return be32toh(m_initackhdr->initTag);
		}

        /**
         * @return the Advertised Receiver Window
         */
		uint32_t getA_rwnd()
		{
			if (m_initackhdr == NULL)
				return 0;
			else
				return be32toh(m_initackhdr->a_rwnd);
		}

        /**
         * @return the outbound stream count
         */
		uint16_t getOutboundStream()
		{
			if (m_initackhdr == NULL)
				return 0;
			else
				return be16toh(m_initackhdr->outbound);
		}

        /**
         * @return the inbound stream count
         */
		uint16_t getInboundStream()
		{
			if (m_initackhdr == NULL)
				return 0;
			else
				return be16toh(m_initackhdr->inbound);
		}

        /**
         * @return the initial TSN
         */
		uint32_t getInitiateTSN()
		{
			if (m_initackhdr == NULL)
				return 0;
			else
				return be32toh(m_initackhdr->initTsn);
		}

        /**
         * @return the pointer to cookie data
         */
		uint8_t* getStateCookie()
		{
			return m_cookieData;
		}

        /**
         * @return the cookie size
         */
		size_t getStateCookieSize()
		{
			return m_cookieSize;
		}

        /**
         * @return the list of IPv4 addresses
         */
		std::list<std::shared_ptr<IPv4Address>> getIPv4Addresses()
		{
			return m_ipv4s;
		}

        /**
         * @return the list of IPv6 addresses
         */
		std::list<std::shared_ptr<IPv6Address>> getIPv6Addresses()
		{
			return m_ipv6s;
		}

        /**
         * @return the list of HostNames
         */
		std::list<std::shared_ptr<std::string>> getHostNames()
		{
			return m_hostnames;
		}

        /**
         * @return the list of unrecognized parameters
         */
		std::list<std::shared_ptr<SctpParam>> getUnrecognizedParameters()
		{
			return m_unrecognizedParameters;
		}
        
        virtual void parseChunkData();

	private:
		initackchunkhdr *m_initackhdr;
        
		std::list<std::shared_ptr<IPv4Address>> m_ipv4s;
		std::list<std::shared_ptr<IPv6Address>> m_ipv6s;
		std::list<std::shared_ptr<std::string>> m_hostnames;
		std::list<std::shared_ptr<SctpParam>> m_unrecognizedParameters;
		uint8_t* m_cookieData;
		size_t m_cookieSize;

    };

    /**
     * @class SctpSAckChunk
     * A wrapper class for SCTP SACK chunk.
     */
	class SctpSAckChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpSAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpSAckChunk() { }

        /**
         * @return the cumulative tag
         */
		uint32_t getCumulativeTag()
		{
			if (m_sackhdr == NULL)
				return 0;
			else
				return be32toh(m_sackhdr->cumulativeTag);
		}

        /**
         * @return the Advertised Receiver Window
         */
		uint32_t getA_rwnd()
		{
			if (m_sackhdr == NULL)
				return 0;
			else
				return be32toh(m_sackhdr->a_rwnd);
		}

        uint16_t getGapBlockCount()
        {
            if (m_sackhdr == NULL)
                return 0;
            else
                return be16toh(m_sackhdr->gapAck);
        }

        uint16_t getDuplicateTsnCount()
        {
            if (m_sackhdr == NULL)
                return 0;
            else
                return be16toh(m_sackhdr->dupTsn);
        }

        /**
         * @return the i'th gap start
         */
        uint16_t getGapStart(int i)
        {
            if ((i >= 0) && (i < getGapBlockCount())) {
                return be16toh((m_gapBlocks + i)->start);
            } else return 0;
        }
        
        /**
         * @return the i'th gap end
         */
        uint16_t getGapEnd(int i)
        {
            if ((i >= 0) && (i < getGapBlockCount())) {
                return be16toh((m_gapBlocks + i)->end);
            } else return 0;
        }
        
        /**
         * @return the i'th duplicate TSNs
         */
		uint32_t getDupTsn(int i)
        {
            if ((i >= 0) && (i < getDuplicateTsnCount())) {
                return be32toh(*(m_dupTsns + i));
            } else return 0;
        }

	private:
		sackchunkhdr *m_sackhdr;
        
        sackgapblock *m_gapBlocks;
        uint32_t *m_dupTsns;
        
    };

    /**
     * @class SctpHbChunk
     * A wrapper class for SCTP Heartbeat chunk.
     */
	class SctpHbChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpHbChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpHbChunk() {}

        /**
         * @return the pointer to heartbeat info
         */
		uint8_t* getHbInfo()
		{
			return m_hbInfo;
		}

        /**
         * @return the heartbeat size
         */
		size_t getHbInfoSize()
		{
			return m_hbInfoSize;
		}
        
        virtual void parseChunkData();

	private:
		uint8_t* m_hbInfo;
		size_t m_hbInfoSize;

    };

    /**
     * @class SctpHbAckChunk
     * A wrapper class for SCTP Heartbeat ack chunk.
     */
	class SctpHbAckChunk : public SctpHbChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpHbAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpHbAckChunk() {}
        
    };

    /**
     * @class SctpAbortChunk
     * A wrapper class for SCTP Abort chunk.
     */
	class SctpAbortChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpAbortChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpAbortChunk()
        {
            m_errors.clear();
        }

        /**
         * return the verification tag
         */
		bool isVerificationTag()
		{
			if (m_hdr == NULL)
				return false;
			else
				return m_hdr->flag & 0x01;
		}

        /**
         * @return the list of error causes
         */
		std::list<std::shared_ptr<SctpParam>> getErrorCauses()
		{
			return m_errors;
		}
        
        virtual void parseChunkData();

	private:
		std::list<std::shared_ptr<SctpParam>> m_errors;

    };

    /**
     * @class SctpShutdownChunk
     * A wrapper class for SCTP Shutdown chunk.
     */
	class SctpShutdownChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpShutdownChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpShutdownChunk() {}

        /**
         * @return the cumulative TSN Ack
         */
		uint32_t getCumulativeTsnAck()
		{
			return m_cumulativeTsnAck;
		}

	private:
		uint32_t m_cumulativeTsnAck;

    };

    /**
     * @class SctpShutdownAckChunk
     * A wrapper class for SCTP Shutdown ACK chunk.
     */
	class SctpShutdownAckChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpShutdownAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpShutdownAckChunk() {}

    };

    /**
     * @class SctpErrorChunk
     * A wrapper class for SCTP Error chunk.
     */
	class SctpErrorChunk : public SctpChunk
	{
	public:

        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpErrorChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpErrorChunk()
        {
            m_errors.clear();
        }

        /**
         * @return the list of error causes
         */
		std::list<std::shared_ptr<SctpParam>> getErrorCauses()
		{
			return m_errors;
		}
        
        virtual void parseChunkData();

	private:
		std::list<std::shared_ptr<SctpParam>> m_errors;

    };

    /**
     * @class SctpCookieEchoChunk
     * A wrapper class for SCTP Cookie Echo chunk.
     */
	class SctpCookieEchoChunk : public SctpChunk
	{
	public:
        
        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpCookieEchoChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpCookieEchoChunk() {}

        /**
         * @return the pointer to cookie data
         */
		uint8_t* getCookie()
		{
			return m_cookie;
		}

        /**
         * @return the cookie size
         */
		size_t getCookieSize()
		{
			return m_cookieSize;
		}

	private:
		uint8_t* m_cookie;
		size_t m_cookieSize;

    };

    /**
     * @class SctpCookieAckChunk
     * A wrapper class for SCTP Cookie ACK chunk.
     */
	class SctpCookieAckChunk : public SctpChunk
	{
	public:
        
        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpCookieAckChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpCookieAckChunk() {}

    };

    /**
     * @class SctpShutdownCompChunk
     * A wrapper class for SCTP Shutdown Complete chunk.
     */
	class SctpShutdownCompChunk : public SctpChunk
	{
	public:
        
        /**
         * A c'tor for this class that gets a pointer to the parameter raw data (byte array)
         */
		SctpShutdownCompChunk(uint8_t* data, size_t dataLen, commonchunkhdr *hdr, SctpLayer *sctpLayer);

        /**
         * A d'tor for this class, currently does nothing
         */
		~SctpShutdownCompChunk() {}

        /**
         * return the verification tag
         */
		bool isVerificationTag()
		{
			if (m_hdr == NULL)
				return false;
			else
				return m_hdr->flag & 0x01;
		}

    };

	/**
	 * @class SctpLayer
	 * Represents a SCTP (Stream Control Transmission Protocol) protocol layer
	 */
	class SctpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref sctphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		~SctpLayer() {}

		/**
		 * Get a pointer to the SCTP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref sctphdr
		 */
		sctphdr* getSctpHeader() const { return (sctphdr*)m_Data; }

		/**
		 * @return SCTP source port
		 */
		uint16_t getSrcPort() const;

		/**
		 * @return SCTP destination port
		 */
		uint16_t getDstPort() const;

        /**
         * @return the SCTP verification tag
         */
        uint32_t getVerficationTag() const;

        /**
         * @return the SCTP Checksum
         */
        uint32_t getChecksum() const;
        
		/**
		 * @return The number of SCTP chunks in this layer
		 */
		std::list<std::shared_ptr<SctpChunk>> getSctpChunks()
        {
            return m_sctpChunks;
        }

        std::string toString() const;

        // implement abstract methods

		/**
		 * last layer - the next layer are in SCTP chunks
		 */
		void parseNextLayer() {}

		/**
		 * @return Size of @ref sctphdr
		 */
		size_t getHeaderLen() const { return sizeof(sctphdr);}

		/**
		 * Calculate @ref sctphdr#headerChecksum field
		 */
		void computeCalculateFields() {}

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }

        /**
         * The static method makes validation of input data using the checksum
         * @param[in] data The pointer to the beginning of byte stream of SCTP packet
         * @param[in] dataLen The length of byte stream
         * @return True if the data is valid and can represent a SCTP packet
         */
        static inline bool isDataValid(const uint8_t* data, size_t dataLen);
        
	private:
        
        std::list<std::shared_ptr<SctpChunk>> m_sctpChunks;
	};


	// implementation of inline methods

	bool SctpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
        return dataLen > sizeof(sctphdr);
	}

} // namespace pcpp

#endif /* PACKETPP_SCTP_LAYER */
