/*
 * Multiplatform Async Network Library
 * Copyright (c) 2007 Burlex
 *
 * Socket implementable class.
 *
 */

#include "../../include/molnet/Network.h"

#include "netallocator/NedAllocatorImpl.h"
#include "html5/sha1.h"
#include "html5/base64.h"
#include "html5/WebsocketDataMessage.h"
#include "html5/WebsocketHandshakeMessage.h"

#pragma pack(push, 1)
typedef struct
{
	uint16 opcode;
	uint32 size;
	uint16 compresss;
	uint32 checksum;
}logonpacket;
#pragma pack(pop)

initialiseSingleton(SocketGarbageCollector);

MolNetworkUpdate *m_NetworkUpdate = NULL;

unsigned int GetTickCount()
{
    struct timeval tv;
    if(gettimeofday(&tv,NULL) != 0)
        return 0;

    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

Socket::Socket(SOCKET fd, uint32 sendbuffersize, uint32 recvbuffersize) : m_fd(fd), m_connected(false),	m_deleted(false), m_writeLock(0)
{
	// Allocate Buffers
	readBuffer.Allocate(recvbuffersize);
	writeBuffer.Allocate(sendbuffersize);

	m_BytesSent = 0;
	m_BytesRecieved = 0;
	m_html5connected.SetVal(false);
	m_htmlMsgProcessed.SetVal(false);
	memset(&m_packetheard,0,sizeof(m_packetheard));

	// IOCP Member Variables
#ifdef CONFIG_USE_IOCP
	m_completionPort = 0;
#endif

	m_eventCount.SetVal(0);
	isRealRemovedFromSet.SetVal(false);

	// Check for needed fd allocation.
	if(m_fd == 0)
	{
		m_fd = SocketOps::CreateTCPFileDescriptor();
	}

	m_heartJitter = time(NULL);
	m_readTimer.SetVal(0);
	m_readMsgCount.SetVal(0);
	m_readMsgBool.SetVal(true);

	m_buffer_pos = 0;
    masksOffset = 0;
    payloadSize = 0;

	remaining=0;
	compress=0;
	opcode = 0;
	mchecksum = 0;

	sLog.outDebug("Created Socket %u", m_fd);
}

Socket::~Socket()
{
}

bool Socket::Connect(const char* Address, uint32 Port)
{
	struct hostent* ci = gethostbyname(Address);
	if(ci == 0)
		return false;

	m_client.sin_family = ci->h_addrtype;
	m_client.sin_port = ntohs((u_short)Port);
	memcpy(&m_client.sin_addr.s_addr, ci->h_addr_list[0], ci->h_length);

	SocketOps::Blocking(m_fd);
	if(connect(m_fd, (const sockaddr*)&m_client, sizeof(m_client)) == -1)
		return false;

	// at this point the connection was established
#ifdef CONFIG_USE_IOCP
	m_completionPort = sSocketMgr.GetCompletionPort();
#endif
	_OnConnect();
	return true;
}

void Socket::Accept(sockaddr_in* address)
{
	memcpy(&m_client, address, sizeof(*address));
	_OnConnect();
}

void Socket::_OnConnect()
{
	// set common parameters on the file descriptor
	SocketOps::Nonblocking(m_fd);
	SocketOps::DisableBuffering(m_fd);
	/*	SocketOps::SetRecvBufferSize(m_fd, m_writeBufferSize);
		SocketOps::SetSendBufferSize(m_fd, m_writeBufferSize);*/
	m_connected.SetVal(true);

	// IOCP stuff
#ifdef CONFIG_USE_IOCP
	AssignToCompletionPort();
	SetupReadEvent();
#endif
	sSocketMgr.AddSocket(this);

	// Call virtual onconnect
	OnConnect();
}

bool Socket::Send(CMolMessageOut &out)
{
	if(out.getLength() <= 0 || out.getLength() > MOL_REV_BUFFER_SIZE_TWO)
		return false;

	if(IsConnected() == false || IsDeleted() == true) return false;

	//int pSendCount = 5;
	bool rv = true;

	//while(pSendCount > 0)
	//{
	try
	{
		BurstBegin();
        uint8 SendbufferData[MOL_REV_BUFFER_SIZE_TWO];
        memset(SendbufferData,0,MOL_REV_BUFFER_SIZE_TWO);

        int uSendSize = out.getLength();
        memcpy(SendbufferData+sizeof(logonpacket),(uint8*)out.getData(),uSendSize);
        //Encrypto(bufferData,uSendSize);

		uint16 pchecksum = checksum((uint16*)(SendbufferData+sizeof(logonpacket)), uSendSize);

        //加密
        int len = Rc4Encrypt(RC4_KEY, (uint8*)SendbufferData+sizeof(logonpacket),(uint8*)SendbufferData+sizeof(logonpacket), uSendSize );

        bool isCompress = false;

        ////压缩
        //if(len > 1024)
        //{
        //	isCompress = true;
        //	len = mole2d::network::CompressData((uint8*)SendbufferData+sizeof(logonpacket),(uint8*)SendbufferData+sizeof(logonpacket), len);
        //}

        logonpacket header;
        header.opcode = MOL_NETWORK_VERSION;
        header.size = len;
        header.compresss = (int)isCompress;
		header.checksum = pchecksum;

        if(len + sizeof(logonpacket) < MOL_REV_BUFFER_SIZE_TWO)
        {
            // 先拷贝包头
            memcpy(SendbufferData,&header,sizeof(logonpacket));

            rv = BurstSend(SendbufferData,len + sizeof(logonpacket));
        }

        if(rv)
            BurstPush();
        BurstEnd();
	}
	catch (std::exception e)
	{
		BurstEnd();

		char str[256];
		sprintf(str,"发送数据异常:%s\n",e.what());
		LOG_DEBUG(str);
	}

	return rv;
}

bool Socket::Send(const uint8* Bytes, uint32 Size)
{
	bool rv;

	// This is really just a wrapper for all the burst stuff.
	BurstBegin();
	rv = BurstSend(Bytes, Size);
	if(rv)
		BurstPush();
	BurstEnd();

	return rv;
}

bool Socket::SendHtml5(const uint8 * Bytes,uint32 Size)
{
	if(Bytes == NULL || Size <= 0)
		return false;

	CMolMessageOut out;

	int64 payloadSize = Size;

	int expectedSize = payloadSize + 1; //flags byte.
	if(payloadSize <= 125  && payloadSize <= 65535 )
		expectedSize += 1;
	else if(payloadSize > 125  && payloadSize <= 65535)
		expectedSize += 3;
	else
		expectedSize += 9;

	//create the flags byte
	uint8 payloadFlags = 129;
	out.writeBytes(&payloadFlags, 1);

	//create the length byte
	if (payloadSize <= 125)
	{
		uint8 basicSize = payloadSize;
		out.writeBytes(&basicSize, 1);
	}
	else if (payloadSize > 125 & payloadSize <= 65535)
	{
		uint8 basicSize = 126;
		out.writeBytes(&basicSize, 1);

		uint8 len[2];
		len[0] = ( payloadSize >> 8 ) & 255;
		len[1] = ( payloadSize ) & 255;
		out.writeBytes(len, 2);
	}
	else
	{
		uint8 basicSize = 127;
		out.writeBytes(&basicSize, 1);

		uint8 len[8];
		len[0] = ( payloadSize >> 56 ) & 255;
		len[1] = ( payloadSize >> 48  ) & 255;
		len[2] = ( payloadSize >> 40 ) & 255;
		len[3] = ( payloadSize >> 32  ) & 255;
		len[4] = ( payloadSize >> 24 ) & 255;
		len[5] = ( payloadSize >> 16  ) & 255;
		len[6] = ( payloadSize >> 8 ) & 255;
		len[7] = ( payloadSize ) & 255;
		out.writeBytes(len, 8);
	}

	out.writeBytes((uint8*)Bytes,payloadSize);

	return Send((const uint8*)out.getData(),out.getLength());
}

bool Socket::BurstSend(const uint8* Bytes, uint32 Size)
{
	return writeBuffer.Write(Bytes, Size);
}

string Socket::GetRemoteIP()
{
	char* ip = (char*)inet_ntoa(m_client.sin_addr);
	if(ip != NULL)
		return string(ip);
	else
		return string("noip");
}

void Socket::Disconnect()
{
	//if returns false it means it's already disconnected
	if(!m_connected.SetVal(false))
		return;

	sLog.outDebug("Socket::Disconnect on socket %u", m_fd);

	// remove from mgr
	//sSocketMgr.RemoveSocket(this);

	// Call virtual ondisconnect
	OnDisconnect();

	if(!IsDeleted())
		Delete();
}

void Socket::Delete()
{
	//if returns true it means it's already delete
	if(m_deleted.SetVal(true))
		return;

	sLog.outDebug("Socket::Delete() on socket %u", m_fd);

	if(IsConnected()) Disconnect();

	//SocketOps::CloseSocket(m_fd);

	//sSocketGarbageCollector.QueueSocket(this);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 构造函数
 *
 * @param fd socket的文件描述
 */
NetClient::NetClient(SOCKET fd)
: Socket(fd, 245760, 327680)
{

}

/**
 * 析构函数
 */
NetClient::~NetClient()
{

}

/**
 * 当数据达到时调用
 *
 * @param size 接收到的数据的大小
 */
void NetClient::OnRead(uint32 size)
{
	try
	{		
		m_heartJitter = time(NULL);

		//printf("NetClient::OnRead1:%d\n",size);
		LOG_ERROR("m_html5connected.GetVal():%d",m_html5connected.GetVal());
		if(m_html5connected.GetVal() == false)
		{
			GetReadBuffer().Read((uint8*)m_buffer+m_buffer_pos,size);
			m_buffer_pos += size;
			//LOG_ERROR("m_buffer:%s", m_buffer);
			WebsocketHandshakeMessage request(m_buffer,m_buffer_pos);

			if(request.Parse())
			{
				WebsocketHandshakeMessage response;

				std::string server_key = request.GetField("Sec-WebSocket-Key");
				server_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

				SHA1        sha;
				unsigned int    message_digest[5];

				sha.Reset();
				sha << server_key.c_str();

				sha.Result(message_digest);

				for (int i = 0; i < 5; i++) {
					message_digest[i] = htonl(message_digest[i]);
				}

				server_key = base64_encode(
					reinterpret_cast<const unsigned char*>
					(message_digest),20
					);

				response.SetField("Upgrade", "websocket");
				response.SetField("Connection", "Upgrade");
				response.SetField("Sec-WebSocket-Accept", server_key);

				std::string responsestr = response.Serialize();
				Send((const uint8*)responsestr.c_str(),responsestr.length());

				m_buffer_pos=0;
				m_html5connected.SetVal(true);
				memset(&m_packetheard,0,sizeof(m_packetheard));

				LOG_ERROR("PushMessage11:");

				sSocketMgr.PushMessage(MessageStru(MES_TYPE_ON_CONNECTED,(uint32)GetFd()));
			}

			return;
		}

		while(true)
		{
		    LOG_ERROR("m_htmlMsgProcessed.GetVal():%d", m_htmlMsgProcessed.GetVal());
		    if(m_htmlMsgProcessed.GetVal() == false)
		    {
		    	if(m_packetheard.payloadFlags == 0 && m_packetheard.basicSize == 0) {
			    	if(GetReadBuffer().GetSize() < 2) {
				    LOG_ERROR("GetReadBuffer().GetSize() < 2");
			            return;
			    	}

			        GetReadBuffer().Read((uint8*)m_buffer+m_buffer_pos,2);
			        m_buffer_pos += 2;
				LOG_ERROR("m_buffer_pos:%d", m_buffer_pos);
			        m_packetheard.payloadFlags = m_buffer[0];
				LOG_ERROR("m_packetheard.payloadFlags:%d", m_packetheard.payloadFlags);
			        if (m_packetheard.payloadFlags != 129){
			        	memset(&m_packetheard,0,sizeof(m_packetheard));
				    LOG_ERROR("m_packetheard.payloadFlags != 129");

				    //wxl modify 
				    masksOffset = 0;
		    		    payloadSize = 0;
		    		    m_buffer_pos = 0;
				    m_htmlMsgProcessed.SetVal(false);
				    memset(&m_packetheard,0,sizeof(m_packetheard));
				    //deallocBytes(payload);
				    //payload = NULL;
				    continue;
			            //return;
			        }

			        m_packetheard.basicSize = m_buffer[1] & 0x7F;		    		
		    	}


		        if (m_packetheard.basicSize <= 125)
		        {
		            payloadSize = m_packetheard.basicSize;
		            masksOffset = 2;
		        }
		        else if (m_packetheard.basicSize == 126)
		        {
		            if (GetReadBuffer().GetSize() < 2){
				LOG_ERROR("22 GetReadBuffer().GetSize() < 2");
		                return;
		            }

			        GetReadBuffer().Read((uint8*)m_buffer+m_buffer_pos,2);
			        m_buffer_pos += 2;

		            payloadSize = ntohs( *(u_short*) (m_buffer + 2) );
		            masksOffset = 4;
		        }
		        else if (m_packetheard.basicSize == 127)
		        {
		            if (GetReadBuffer().GetSize() < 8) {
				LOG_ERROR("22 GetReadBuffer().GetSize() < 8");
		                return;
		            }

			        GetReadBuffer().Read((uint8*)m_buffer+m_buffer_pos,8);
			        m_buffer_pos += 8;

		            payloadSize = ntohl( *(u_long*) (m_buffer + 2) );
		            masksOffset = 10;
		        }
		        else {
			    LOG_ERROR("333 GetReadBuffer().GetSize()");
		            return;
		        }

		        m_htmlMsgProcessed.SetVal(true);
		    }

            if (GetReadBuffer().GetSize()  < payloadSize+4)
            {
		LOG_ERROR("GetReadBuffer().GetSize()  < payloadSize+4");
                return;
            }

	        GetReadBuffer().Read((uint8*)m_buffer+m_buffer_pos,payloadSize+4);
	        m_buffer_pos += (payloadSize+4);

		    uint8 masks[4];
		    memcpy(masks, m_buffer + masksOffset, 4);

		    char* payload = (char*)allocBytes((payloadSize + 1) * sizeof(char));
		    memcpy(payload, m_buffer + masksOffset + 4, payloadSize);
		    for (int64 i = 0; i < payloadSize; i++) {
		        payload[i] = (payload[i] ^ masks[i%4]);
		    }
			payload[payloadSize] = '\0';

			if(m_buffer_pos > 0 && m_buffer_pos < MOL_REV_BUFFER_SIZE_TWO)
			{
				if(m_readTimer.GetVal() == 0)
				{
					m_readTimer.SetVal((ulong)time(NULL));
				}

				ulong tmpTime = (ulong)time(NULL) - m_readTimer.GetVal();

				
				LOG_ERROR("tmpTime:%d", tmpTime);
				LOG_ERROR("IDD_SECOND_MSG_MAX_COUNT:%d", IDD_SECOND_MSG_MAX_COUNT);
				if(tmpTime > 1)
				{
					LOG_ERROR("m_readMsgCount.GetVal():%d", m_readMsgCount.GetVal());
					if(m_readMsgCount.GetVal() > IDD_SECOND_MSG_MAX_COUNT)
					{
						m_readMsgBool.SetVal(false);
					}
					else
					{
						m_readTimer.SetVal(0);
						m_readMsgCount.SetVal(0);
					}
				}
				LOG_ERROR("tmpTime:%d", tmpTime);
				if(tmpTime > 60)
				{
					m_readTimer.SetVal(0);
					m_readMsgCount.SetVal(0);
					m_readMsgBool.SetVal(true);
				}

				if(m_readMsgBool.GetVal())
				{
					CMolMessageIn *in = NULL;

					try
					{
						in = new CMolMessageIn(payload,payloadSize + 1);
					}
					catch (std::exception e)
					{
						char str[256];
						sprintf(str,"%s:\n",e.what());
						LOG_DEBUG(str);
						//perr->Delete();

						if(in)
						{
							SafeDelete(in);
							in = NULL;
						}
					}
					LOG_ERROR("in 333");
					if(in)
					{
						LOG_ERROR("atoi(payload):%d", atoi(payload));
						if(atoi(payload) == IDD_MESSAGE_HEART_BEAT)
						{
							//printf("MES_TYPE_ON_READ1:%s\n",payload);
							SafeDelete(in);
							in = NULL;
						}
						else
						{
							//printf("MES_TYPE_ON_READ2:%s\n",payload);
							sSocketMgr.PushMessage(MessageStru(MES_TYPE_ON_READ,(uint32)GetFd(),in));
							//ServerGameFrameManager.OnProcessNetMes(this,in);
						}

						++m_readMsgCount;
					}
				}
			}

		    masksOffset = 0;
		    payloadSize = 0;
		    m_buffer_pos = 0;
			m_htmlMsgProcessed.SetVal(false);
			memset(&m_packetheard,0,sizeof(m_packetheard));
			deallocBytes(payload);
			payload = NULL;
		}
	}
	catch (std::exception e)
	{
		//m_readMutex.Release();
		char str[256];
		sprintf(str,"接收数据异常%s:\n",e.what());
		LOG_ERROR(str);

		// 关闭这个客户端
		Disconnect();
	}

	//m_readMutex.Acquire();
/*	while(true)
	{
		try
		{
			if(!remaining)
			{
				if(GetReadBuffer().GetSize() < sizeof(logonpacket))
				{
					//m_readMutex.Release();
					return;
				}

				// 首先取得版本号
				GetReadBuffer().Read((uint8*)&opcode,sizeof(uint16));

				if(opcode != MOL_NETWORK_VERSION)
				{
					//m_readMutex.Release();
					// 如果版本号不对，关闭这个客户端
					Disconnect();
					return;
				}

				// 首先取得包头
				GetReadBuffer().Read((uint8*)&remaining,sizeof(uint32));

				// 取得数据压缩标志
				GetReadBuffer().Read((uint8*)&compress,sizeof(uint16));


				// 取得数据效验标志
				GetReadBuffer().Read((uint8*)&mchecksum,sizeof(uint32));
			}

			if(GetReadBuffer().GetSize() < remaining/* || GetReadBuffer().GetSize() >= MOL_REV_BUFFER_SIZE_TWO)
			{
				//m_readMutex.Release();
				return;
			}

			char buffer[MOL_REV_BUFFER_SIZE_TWO];                /**< 用于存储收到的数据
			memset(buffer,0,MOL_REV_BUFFER_SIZE_TWO);

			// 取得实际数据包
			GetReadBuffer().Read((uint8*)buffer,remaining);

			int len = remaining;
			//sSocketMgr.uncompress((unsigned char*)myBuffer,myheader.nDataLen,&dlength);
			//char* rdata = sSocketMgr.uncompress((unsigned char*)buffer,remaining,&dlength);
			//Decrypto((uint8*)buffer,dlength);

			////解压缩
			//if(compress > 0)
			//	len = mole2d::network::UncompressData((uint8*)buffer,(uint8*)buffer, len );

			//解密
			len = Rc4Decrypt(RC4_KEY, (uint8*)buffer,(uint8*)buffer, len );

			//校研数据
			if(mchecksum != checksum((uint16*)buffer, len))
			{
				Disconnect();
				return;
			}

			if(len > 0 && len < MOL_REV_BUFFER_SIZE_TWO)
			{
				m_heartJitter = time(NULL);

				//用于处理客户端的一些攻击行为
				if(m_readTimer.GetVal() == 0)
				{
					m_readTimer.SetVal((ulong)time(NULL));
				}

				ulong tmpTime = (ulong)time(NULL) - m_readTimer.GetVal();

				if(tmpTime > 1)
				{
					if(m_readMsgCount.GetVal() > IDD_SECOND_MSG_MAX_COUNT)
					{
						m_readMsgBool.SetVal(false);
					}
					else
					{
						m_readTimer.SetVal(0);
						m_readMsgCount.SetVal(0);
					}
				}

				if(tmpTime > 60)
				{
					m_readTimer.SetVal(0);
					m_readMsgCount.SetVal(0);
					m_readMsgBool.SetVal(true);
				}

				if(m_readMsgBool.GetVal())
				{
					CMolMessageIn *in = NULL;

					try
					{
						in = new CMolMessageIn(buffer,len);
					}
					catch (std::exception e)
					{
						char str[256];
						sprintf(str,"接收数据异常%s:\n",e.what());
						LOG_DEBUG(str);
						//perr->Delete();

						if(in)
						{
							delete in;
							in = NULL;
						}
					}

					if(in)
					{
						// 如果是心跳信息就不用处理了
						if(in->getId() == IDD_MESSAGE_HEART_BEAT)
						{
							delete in;
							in = NULL;
						}
						else
						{
							sSocketMgr.PushMessage(MessageStru(MES_TYPE_ON_READ,(uint32)GetFd(),in));
							//ServerGameFrameManager.OnProcessNetMes(this,in);
						}

						++m_readMsgCount;
					}
				}
			}

			remaining = 0;
			compress = 0;
			opcode = 0;
			mchecksum = 0;
		}
		catch (std::exception e)
		{
			//m_readMutex.Release();
			char str[256];
			sprintf(str,"接收数据异常%s:\n",e.what());
			LOG_DEBUG(str);

			// 关闭这个客户端
			Disconnect();
		}
	}
	//m_readMutex.Release();*/
}

/**
 * 当一个连接成功建立时调用
 */
void NetClient::OnConnect()
{
	//sSocketMgr.PushMessage(MessageStru(MES_TYPE_ON_CONNECTED,(uint32)GetFd()));
	//ServerGameFrameManager.OnProcessConnectedNetMes(this);
}

/**
 * 当一个连接断开时调用
 */
void NetClient::OnDisconnect()
{
	sSocketMgr.PushMessage(MessageStru(MES_TYPE_ON_DISCONNECTED,(uint32)GetFd()));
	//ServerGameFrameManager.OnProcessDisconnectNetMes(this);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 构造函数
 */
MolNetworkUpdate::MolNetworkUpdate()
: m_curTime(0),m_TimeSpeed(10),m_threadTimer(0),m_threadTimeSpeed(20000),
	m_UpdateTime(0),m_UpdateTimeSpeed(2000)
{

}

/**
 * 析构函数
 */
MolNetworkUpdate::~MolNetworkUpdate()
{

}

bool MolNetworkUpdate::run()
{
	if(m_ServerSocket == NULL) return true;

	while(m_ServerSocket->IsOpen())
	{
		//if(m_curTime == 0)
		//	m_curTime = GetTickCount();

		//if(GetTickCount() > m_curTime + m_TimeSpeed)
		//{
			sSocketMgr.Update();

		//	m_curTime = 0;
		//}

		//if(m_UpdateTime == 0)
		//	m_UpdateTime = GetTickCount();

		//if(GetTickCount() > m_UpdateTime + m_UpdateTimeSpeed)
		//{
			sSocketGarbageCollector.Update();

		//	m_UpdateTime = 0;
		//}

		MolTcpSocketClientManager.Update();			

		if(m_threadTimer == 0)
			m_threadTimer = GetTickCount();

		if(GetTickCount() > m_threadTimer + m_threadTimeSpeed)
		{
			ThreadPool.IntegrityCheck();

			m_threadTimer = 0;
		}

		usleep(1000);
	}

	return false;
}
