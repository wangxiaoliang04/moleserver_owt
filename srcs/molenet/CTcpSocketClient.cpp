#include "CTcpSocketClient.h"
#include "CircularBuffer.h"
#include "MolMessageIn.h"
#include "MolMessageOut.h"
#include "gettimeofday.h"
#include "rc4.h"
#include "ThreadPool.h"
#include "Log.h"

#include "netallocator/NedAllocatorImpl.h"
#include "html5/sha1.h"
#include "html5/base64.h"
#include "html5/WebsocketDataMessage.h"
#include "html5/WebsocketHandshakeMessage.h"

#ifdef _WIN32
	#pragma comment(lib, "ws2_32.lib")
#else

#endif

#pragma pack(push, 1)
typedef struct
{
	uint16 opcode;
	uint32 size;
	uint16 compresss;
	uint32 checksum;
}logonpacket;
#pragma pack(pop)

#define MOL_NETWORK_VERSION 100                     // ������ϢЭ��汾
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1

initialiseSingleton(CTcpSocketClientManager);

static Thread* pThread = NULL;

/// ���캯��
CMolTcpSocketClient::CMolTcpSocketClient()
	:m_Socket(0),m_bConnectState(NOCONNECT),m_ReadBuffer(NULL),
	remaining(0),opcode(0),compress(0),mchecksum(0),sendedhearthintcount(0)
{
	FD_ZERO(&m_readableSet);
	FD_ZERO(&m_writeableSet);
	FD_ZERO(&m_exceptionSet);

	remaining = 0;
	compress = 0;
	opcode = 0;
	mchecksum=0;

	m_html5connected.SetVal(false);
	m_htmlMsgProcessed.SetVal(false);
	m_buffer_pos=0;	
    masksOffset = 0;
    payloadSize = 0;	
    memset(&m_packetheard,0,sizeof(m_packetheard));

	m_readTimer.SetVal(0);
	m_readMsgCount.SetVal(0);
	m_readMsgBool.SetVal(true);    

	m_port=0;

	m_ReadBuffer = new CircularBuffer();
	m_ReadBuffer->Allocate(REV_SIZE);

	m_mainlooprunning=true;
	pThread = ThreadPool.StartThread(this);

#ifdef _WIN32
		gettimeofday(&reconnectHintTime);
#else
		gettimeofday(&reconnectHintTime, NULL);
#endif			
}

/// ��������
CMolTcpSocketClient::~CMolTcpSocketClient(void)
{
	ClearMesList();
	CloseConnect();

	m_mainlooprunning=false;
	ThreadPool.ThreadExit(pThread);

#ifndef _WIN32
	usleep(100000);
#else
	Sleep(1000);
#endif

	delete m_ReadBuffer;
	m_ReadBuffer = NULL;
}

void CMolTcpSocketClient::ExitWorkingThread(void)
{

}

/// �ر�����
void CMolTcpSocketClient::CloseConnect(bool isShow)
{
	if(m_bConnectState == NOCONNECT) return;

	m_ReadBufferLock.Acquire();
	bool bClose = (m_Socket != INVALID_SOCKET);
	m_bConnectState = NOCONNECT;

	if(m_Socket != INVALID_SOCKET)
	{
#ifdef _WIN32
	    shutdown(m_Socket, SD_BOTH);
		LINGER lingerStruct;
		lingerStruct.l_onoff = 1;
		lingerStruct.l_linger = 0;
		setsockopt(m_Socket, SOL_SOCKET, SO_LINGER,
			(char *)&lingerStruct, sizeof(lingerStruct) );
		CancelIo((HANDLE)m_Socket);
		closesocket(m_Socket);
#else
		shutdown(m_Socket, SHUT_RDWR);
		close(m_Socket);
#endif
		m_Socket = INVALID_SOCKET;
	}

	if(m_ReadBuffer && m_ReadBuffer->GetSize() > 0)
		m_ReadBuffer->Remove(m_ReadBuffer->GetSize());

	if(isShow) PushMessage(MessageStru(MES_TYPE_ON_DISCONNECTED,m_Socket));
	m_ReadBufferLock.Release();
	//::OutputDebugString(TEXT("Is running??\n"));
}

/**
 * �����Ϣ�б�
 */
void CMolTcpSocketClient::ClearMesList(void)
{
	if(_MesList.empty()) return;

	_mesLock.Acquire();
	std::list<MessageStru>::iterator iter = _MesList.begin();
	for(;iter!=_MesList.end();++iter)
	{
		if((*iter).mes)
			delete (*iter).mes;
	}
	_MesList.clear();
	_mesLock.Release();
}

/**
 * ��������
 *
 * @param msg Ҫ���͵�����
 *
 * @return �������ݷ��͵��������������ȫ�����ͳɹ��������ݵĴ�С�����򷵻�SOCKET_ERROR
 */
int CMolTcpSocketClient::Send(CMolMessageOut &msg)
{
	if(msg.getData() == NULL ||
		msg.getLength() <= 0 ||
		msg.getLength() >= MOL_REV_BUFFER_SIZE_TWO)
		return SOCKET_ERROR;

	if(m_Socket == INVALID_SOCKET) return SOCKET_ERROR;

	int iSendCount = SOCKET_ERROR;
	int uSended,uSendSize,iErrorCode;

	uSended = iErrorCode = 0;
	uSendSize = msg.getLength();

	char combuf[MOL_REV_BUFFER_SIZE_TWO];
	memset(combuf,0,MOL_REV_BUFFER_SIZE_TWO);

	memcpy(combuf+sizeof(logonpacket),(uint8*)msg.getData(),uSendSize);

	uint16 pchecksum = checksum((uint16*)(combuf+sizeof(logonpacket)), uSendSize);

	int len = Rc4Encrypt(RC4_KEY,(uint8*)combuf+sizeof(logonpacket),(uint8*)combuf+sizeof(logonpacket), uSendSize );

	bool isCompress = false;

	//ѹ��
	//if(len > 1024)
	//{
	//	isCompress = true;
	//	len = mole2d::network::CompressData((uint8*)combuf+sizeof(logonpacket),(uint8*)combuf+sizeof(logonpacket), len);
	//}

	logonpacket header;
	header.opcode = MOL_NETWORK_VERSION;
	header.size = len;
	header.compresss = (int)isCompress;
	header.checksum = pchecksum;

	// �ȿ�����ͷ
	memcpy(combuf,&header,sizeof(logonpacket));

	// ��������
	//Encrypto((unsigned char*)msg.getData(),uSendSize);

    return Send(combuf,uSendSize);
}

int CMolTcpSocketClient::Send(char *msg,uint32 len)
{
    if(msg == NULL || len <= 0)
        return 0;

	if(m_Socket == INVALID_SOCKET) return SOCKET_ERROR;

	int iSendCount = SOCKET_ERROR;
	int uSended,uSendSize,iErrorCode;

	uSended = iErrorCode = 0;

	uSendSize = len;

	_sendLock.Acquire();

	if(uSendSize >= MOL_REV_BUFFER_SIZE_TWO)
	{
		_sendLock.Release();
		return SOCKET_ERROR;
	}

	try
	{
		do
		{
			iErrorCode = ::send(m_Socket,(msg+uSended),uSendSize-uSended,0);
			if(iErrorCode <= SOCKET_ERROR)
			{
#ifdef _WIN32
				if(::WSAGetLastError() == WSAEWOULDBLOCK)
				{
					if(iSendCount++ > 100)
					{
						_sendLock.Release();
						return SOCKET_ERROR;
					}
					else
					{
						Sleep(10);
						continue;
					}
				}
				else
				{
					_sendLock.Release();
					return SOCKET_ERROR;
				}
#else
                if(iSendCount++ > 100)
				{
					_sendLock.Release();
                    return SOCKET_ERROR;
				}
				else
                {
                    usleep(10000);
                    continue;
                }
#endif
			}

			uSended += iErrorCode;
			iSendCount = 0;
		} while (uSended < uSendSize);
	}
	catch(...)
	{

	}
	_sendLock.Release();

	//::OutputDebugString(TEXT("Is running2?\n"));

	return uSendSize;
}

int CMolTcpSocketClient::Sendhtml5(char *Bytes,uint32 Size)
{
	if(Bytes == NULL || Size <= 0 || !IsConnected())
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

	uint8 masks[4];
	masks[0]=0xFF;
	masks[1]=0xFF;
	masks[2]=0xFF;
	masks[3]=0xFF;
	out.writeBytes(masks, 4);	

	char buffer[MOL_REV_BUFFER_SIZE_TWO];
	memcpy(buffer,Bytes,payloadSize);

    for (int64 i = 0; i < payloadSize; i++) {
        buffer[i] = (buffer[i] ^ masks[i%4]);
    }	

	out.writeBytes((uint8*)buffer,payloadSize);

	return Send(out.getData(),out.getLength());
}

/// �������ӷ�����
bool CMolTcpSocketClient::Reconnect(void)
{
	if(IsConnected()) return false;

	struct timeval now;

#ifdef _WIN32
	gettimeofday(&now);
#else
	gettimeofday(&now, NULL);
#endif
	long temp = now.tv_sec - reconnectHintTime.tv_sec;

	if(temp > 5)
	{
#ifdef _WIN32
		gettimeofday(&reconnectHintTime);
#else
		gettimeofday(&reconnectHintTime, NULL);
#endif	

		//LOG_BASIC("server:%s port:%d Reconnection will take place in 10 seconds.",m_ipaddress,m_port);

		return Connect(m_ipaddress,m_port);
	}

	return false;
}


/// ����ָ���ķ�����
bool CMolTcpSocketClient::Connect(std::string ipaddress,int port)
{
	if(ipaddress.empty())
		return false;

	if(IsConnected())
		CloseConnect(true);

	//::OutputDebugString(TEXT("socket running:7.\n"));

	remaining = 0;
	compress = 0;
	opcode = 0;
	mchecksum=0;
	sendedhearthintcount=0;
	ClearMesList();

	strcpy(m_ipaddress,ipaddress.c_str());
	m_port = port;

#ifdef _WIN32
	long dwServerIP = inet_addr(ipaddress.c_str());
	if(dwServerIP == INADDR_NONE)
	{
		LPHOSTENT lpHost = ::gethostbyname(ipaddress.c_str());
		if(lpHost != NULL) return false;

		dwServerIP = ((LPIN_ADDR)(lpHost->h_addr))->s_addr;
	}

	m_Socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	unsigned int option = 1;
	setsockopt(m_Socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&option, 4);

	u_long arg = 1;
	::ioctlsocket(m_Socket, FIONBIO, &arg);

	int time_out = 5000;
	setsockopt(m_Socket,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_out,sizeof(int));
	setsockopt(m_Socket,SOL_SOCKET,SO_SNDTIMEO,(char*)&time_out,sizeof(int));

	sockaddr_in SocketAddr;
	SocketAddr.sin_family = AF_INET;
	SocketAddr.sin_port = htons(port);
	SocketAddr.sin_addr.S_un.S_addr = dwServerIP;

	if((::WSAConnect(m_Socket,(const sockaddr*)(&SocketAddr),sizeof(SocketAddr),NULL,NULL,NULL,NULL) == SOCKET_ERROR) &&
		(::WSAGetLastError() != WSAEWOULDBLOCK))
	{
		CloseConnect(true);
		return false;
	}
#else
    struct hostent * lpHost = gethostbyname(ipaddress.c_str());
    if(lpHost == NULL) return false;

	m_Socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(m_Socket < 0)
        return false;

	unsigned int option = 1;
	setsockopt(m_Socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&option, 4);

	int time_out = 5000;
	setsockopt(m_Socket,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_out,sizeof(int));
	setsockopt(m_Socket,SOL_SOCKET,SO_SNDTIMEO,(char*)&time_out,sizeof(int));

	sockaddr_in SocketAddr;
	SocketAddr.sin_family = AF_INET;
	SocketAddr.sin_port = ntohs((u_short)port);
	memcpy(&SocketAddr.sin_addr.s_addr , lpHost->h_addr_list[0], lpHost->h_length);

    int sockfd = connect(m_Socket,(const sockaddr*)(&SocketAddr),sizeof(SocketAddr)) ;
	if(sockfd < 0)
	{
		//perror("connect fail.");
		CloseConnect();
		return false;
	}

	u_long arg = 1;
	::ioctl(m_Socket, FIONBIO, &arg);	

#endif

	//::OutputDebugString(TEXT("socket running:8.\n"));

	m_bConnectState = CONNECTTING;

	WebsocketHandshakeMessage response;

	response.SetField("Upgrade", "websocket");
	response.SetField("Connection", "Upgrade");
	response.SetField("Sec-WebSocket-Accept", "hj0eNqbhE/A0GkBXDRrYYw==");

	std::string responsestr = response.Serialize();
	Send((char*)responsestr.c_str(),responsestr.length());	

	//::OutputDebugString(TEXT("socket running:9.\n"));
	LOG_BASIC("server:%s port:%d Connection successful.",m_ipaddress,m_port);

	return true;
}

int CMolTcpSocketClient::GetNetMessage(NetMessage & mes,bool isclearmeslist)
{
	if(!IsConnected()) 
	{
		LOG_ERROR("IsConnected(): false");
		return 0;
	}
	
	if(isclearmeslist) mes.Clear();

	if(GetMesCount() <= 0 ||
		mes.GetMaxCount() <= 0)
		return 0;

	//if(!IsConnected()) return 0;

	int count = 0;

	// �����ǰϵͳ�е���Ϣ����С������Ҫ��ȡ�ĸ���ʱ����ȡȫ������Ϣ��
	// �����ȡ�������õ���Ϣ��������Ϣ
	LOG_ERROR("mes.GetMaxCount():%d",mes.GetMaxCount());
	if(GetMesCount() < mes.GetMaxCount())
	{
		if(_mesLock.AttemptAcquire())
		{
			std::list<MessageStru> *meslist = GetMesList();
			if(meslist == NULL || meslist->empty())
			{
				_mesLock.Release();
				return 0;
			}

			std::list<MessageStru>::iterator iter = meslist->begin();
			for(;iter != meslist->end();)
			{
				mes.AddMessage((*iter));
				iter = meslist->erase(iter);
				count+=1;
			}
			_mesLock.Release();
		}
	}
	else
	{
		if(_mesLock.AttemptAcquire())
		{
			std::list<MessageStru> *meslist = GetMesList();
			if(meslist == NULL || meslist->empty())
			{
				_mesLock.Release();
				return 0;
			}

			std::list<MessageStru>::iterator iter = meslist->begin();
			for(int i=0;iter != meslist->end(),i<mes.GetMaxCount();i++)
			{
				if(iter == meslist->end()) break;

				mes.AddMessage((*iter));
				iter = meslist->erase(iter);
				count+=1;
			}

			_mesLock.Release();
		}
	}

	return count;
}

void CMolTcpSocketClient::ProcessSelect(void)
{
	if(!IsConnected())
		return;

	int nfds;
	timeval timeout;
	timeout.tv_usec = 20000;
	timeout.tv_sec = 0;

	FD_ZERO(&m_readableSet);
	FD_ZERO(&m_writeableSet);
	FD_ZERO(&m_exceptionSet);
	FD_SET(m_Socket, &m_readableSet);
	FD_SET(m_Socket, &m_writeableSet);

	nfds = select(FD_SETSIZE, &m_readableSet, &m_writeableSet, &m_exceptionSet, &timeout);

	if(nfds < 0)
	{
#ifdef _WIN32
		printf("Exception in select() somewhere.. :/ %u\n", WSAGetLastError());
#endif
		CloseConnect(true);
	}
	else if(nfds == 0)
	{
		// ������ŷ�5����������ʧ�ܣ���ô�����Ѿ��Ͽ���
		if(sendedhearthintcount >= 5) {			
			CloseConnect(true);
		}
	}
	else if(nfds > 0)
	{
		if(FD_ISSET(m_Socket, &m_readableSet))
		{
			m_ReadBufferLock.Acquire();
			int size = ::recv(m_Socket,(char*)(m_ReadBuffer->GetBuffer()),(int)m_ReadBuffer->GetSpace(),0);
			if(size == SOCKET_ERROR || size == 0)
			{
				CloseConnect(true);
				m_ReadBufferLock.Release();
				return;
			}

			try
			{
				if(size != 0xFFFFFFFF)
					m_ReadBuffer->IncrementWritten(size);

				if(m_html5connected.GetVal() == false)
				{
					if(m_ReadBuffer->GetSize() < 129) 
					{
						m_ReadBufferLock.Release();	
						return;
					}

					m_ReadBuffer->Read((uint8*)m_buffer+m_buffer_pos,129);
					m_buffer_pos += 129;

					WebsocketHandshakeMessage request(m_buffer,m_buffer_pos);

					if(request.Parse())
					{		
						m_buffer_pos=0;
						payloadSize=0;
						m_html5connected.SetVal(true);
						m_bConnectState=CONNECTED;
						memset(&m_packetheard,0,sizeof(m_packetheard));
						PushMessage(MessageStru(MES_TYPE_ON_CONNECTED,m_Socket));
					}					
				}

				while(true)
				{
				    if(m_htmlMsgProcessed.GetVal() == false)
				    {
				    	if(m_packetheard.payloadFlags == 0 && m_packetheard.basicSize == 0) {
					    	if(m_ReadBuffer->GetSize() < 2) 
					    	{
					        	m_ReadBufferLock.Release();
					            return;
					    	}

					        m_ReadBuffer->Read((uint8*)m_buffer+m_buffer_pos,2);
					        m_buffer_pos += 2;

					        m_packetheard.payloadFlags = m_buffer[0];
					        if (m_packetheard.payloadFlags != 129)
					        {
					        	m_ReadBufferLock.Release();
					            return;
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
				            if (m_ReadBuffer->GetSize() < 2)
				            {
				            	m_ReadBufferLock.Release();
				                return;
				            }

					        m_ReadBuffer->Read((uint8*)m_buffer+m_buffer_pos,2);
					        m_buffer_pos += 2;

				            payloadSize = ntohs( *(u_short*) (m_buffer + 2) );
				            masksOffset = 4;
				        }
				        else if (m_packetheard.basicSize == 127)
				        {
				            if (m_ReadBuffer->GetSize()  < 8)
				            {
				            	m_ReadBufferLock.Release();
				                return;
				            }

					        m_ReadBuffer->Read((uint8*)m_buffer+m_buffer_pos,8);
					        m_buffer_pos += 8;

				            payloadSize = ntohl( *(u_long*) (m_buffer + 2) );
				            masksOffset = 10;
				        }
				        else
				        {
				        	m_ReadBufferLock.Release();
				            return;
				        }

				        m_htmlMsgProcessed.SetVal(true);
				    }

		            if (m_ReadBuffer->GetSize()  < payloadSize)
		            {
		            	m_ReadBufferLock.Release();
		                return;
		            }

			        m_ReadBuffer->Read((uint8*)m_buffer+m_buffer_pos,payloadSize);
			        m_buffer_pos += payloadSize;

				    //uint8 masks[4];
				    //memcpy(masks, m_buffer + masksOffset, 4);

				    char* payload = (char*)allocBytes((payloadSize + 1) * sizeof(char));
				    memcpy(payload, m_buffer + masksOffset, payloadSize);
				    //for (int64 i = 0; i < payloadSize; i++) {
				    //    payload[i] = (payload[i] ^ masks[i%4]);
				    //}
					payload[payloadSize] = '\0';	            

					if(m_buffer_pos > 0 && m_buffer_pos < MOL_REV_BUFFER_SIZE_TWO)
					{
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

							if(in)
							{
								if(atoi(in->getData()) == IDD_MESSAGE_HEART_BEAT)
								{
									SafeDelete(in);
									in = NULL;
								}
								else
								{
									PushMessage(MessageStru(MES_TYPE_ON_READ,m_Socket,in));
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

				/*while(true)
				{
					if(!remaining)
					{
						if(m_ReadBuffer->GetSize() < sizeof(logonpacket))
						{
							m_ReadBufferLock.Release();
							return;
						}

						m_ReadBuffer->Read((unsigned char*)&opcode,sizeof(unsigned short));

						if(opcode != MOL_NETWORK_VERSION)
						{
							CloseConnect(true);
							m_ReadBufferLock.Release();
							return;
						}

						m_ReadBuffer->Read((unsigned char*)&remaining,sizeof(unsigned int));

						m_ReadBuffer->Read((unsigned char*)&compress,sizeof(unsigned short));

						m_ReadBuffer->Read((uint8*)&mchecksum,sizeof(uint32));
					}

					if(m_ReadBuffer->GetSize() < remaining/* || m_ReadBuffer->GetSize() >= MOL_REV_BUFFER_SIZE)
					{
						//size_t length = m_ReadBuffer->GetSize();

						//CloseConnect();

						//if(m_BaseFrame)
						//{
						//	m_BaseFrame->OnProcessNetMessage(m_bConnectState,in);
						//}
						m_ReadBufferLock.Release();
						return;
					}

					m_bConnectState = MESPROCESS;
					char buffer[MOL_REV_BUFFER_SIZE_TWO];
					memset(buffer,0,MOL_REV_BUFFER_SIZE_TWO);

					m_ReadBuffer->Read((unsigned char*)buffer,remaining);

					int len = remaining;
					//Decrypto((unsigned char*)buffer,dlength);

					//if(compress > 0)
					//	len = mole2d::network::UncompressData((uint8*)buffer,(uint8*)buffer, len );

					len = Rc4Decrypt(RC4_KEY,(uint8*)buffer,(uint8*)buffer, len );

					if(mchecksum != checksum((uint16*)buffer, len))
					{
						CloseConnect(true);
						m_ReadBufferLock.Release();
						return;
					}

					if(len > 0 && len < MOL_REV_BUFFER_SIZE_TWO)
						PushMessage(MessageStru(MES_TYPE_ON_READ,m_Socket,new CMolMessageIn(buffer,len)));

					remaining = 0;
					compress = 0;
					opcode = 0;
					mchecksum = 0;
				}*/
			}
			catch (...)
			{
				CloseConnect(true);
			}
			m_ReadBufferLock.Release();
		}

		if(FD_ISSET(m_Socket, &m_writeableSet))
		{

		}

		if(FD_ISSET(m_Socket, &m_exceptionSet)) {			
			CloseConnect(true);
		}
	}
}

void CMolTcpSocketClient::GameMainLoop(void)
{
	//::OutputDebugString(TEXT("socket running:1.\n"));

#ifdef _WIN32
		gettimeofday(&lostHeartHintTime);
#else
		gettimeofday(&lostHeartHintTime, NULL);
#endif

	while(IsConnected())
	{
		//::OutputDebugString(TEXT("socket running:5.\n"));

#ifdef _WIN32
		MSG msg;   //����һ��MSG�ı���msg��������Ϣ
		if(PeekMessage(&msg,NULL,0,0,PM_REMOVE)){      //����Ϣ���������Ϣ�������msg
			if(msg.message==WM_QUIT){     //����յ���ֹ��Ϣ���˳�
				break;      //�߳��������أ����ͷžֲ��������ڴ���Դ
			}
		}
#endif

		//::OutputDebugString(TEXT("socket running:2.\n"));

		ProcessSelect();

		//::OutputDebugString(TEXT("socket running:3.\n"));

		// �����������������Ϣ
		struct timeval now;

#ifdef _WIN32
		gettimeofday(&now);
#else
		gettimeofday(&now, NULL);
#endif
		long temp = now.tv_sec - lostHeartHintTime.tv_sec;
		if(temp > 1)
		{
#ifdef _WIN32
		gettimeofday(&lostHeartHintTime);
#else
		gettimeofday(&lostHeartHintTime, NULL);
#endif

			//CMolMessageOut out(100);
			char heartout[] = "100";
			if(Sendhtml5(heartout,strlen(heartout)) == SOCKET_ERROR)
				sendedhearthintcount+=1;
			else
				sendedhearthintcount=0;
		}

#ifdef _WIN32
		Sleep(1);
#else
		usleep(1000);
#endif

		//::OutputDebugString(TEXT("socket running:4.\n"));
	}
}

bool CMolTcpSocketClient::run()
{
	while(m_mainlooprunning)
	{
		GameMainLoop();

#ifdef _WIN32
		Sleep(1);
#else
		usleep(1000);
#endif
	}

	return true;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

CTcpSocketClientManager::CTcpSocketClientManager()
{
#ifdef _WIN32
	unsigned short versionRequested = MAKEWORD (2, 2);
	WSADATA wsaData;

	if (WSAStartup (versionRequested, & wsaData))
		return;

	if (LOBYTE (wsaData.wVersion) != 2||
		HIBYTE (wsaData.wVersion) != 2)
	{
		WSACleanup ();
		return;
	}
#else

#endif

	ThreadPool.Startup();
}

CTcpSocketClientManager::~CTcpSocketClientManager()
{
	ExitWorkingThread();
	deleteAllTcpSocketClient();
	ThreadPool.Shutdown();

#ifdef _WIN32
	WSACleanup ();
#else

#endif
}

void CTcpSocketClientManager::ExitWorkingThread(void)
{
	if(m_TcpSocketClients.empty())
		return;

	for(int i=0;i<(int)m_TcpSocketClients.size();i++)
	{
		if(m_TcpSocketClients[i])
		{
			m_TcpSocketClients[i]->ExitWorkingThread();
			//ThreadPool.KillFreeThreads(ThreadPool.GetFreeThreadCount());
		}
	}
}

void CTcpSocketClientManager::deleteAllTcpSocketClient(void)
{
	if(m_TcpSocketClients.empty())
		return;

	for(int i=0;i<(int)m_TcpSocketClients.size();i++)
	{
		if(m_TcpSocketClients[i]) delete m_TcpSocketClients[i];
		m_TcpSocketClients[i] = NULL;
	}

	m_TcpSocketClients.clear();
}

void CTcpSocketClientManager::GetNetMessage(NetMessage & mes,bool isclearmeslist)
{
	if(m_TcpSocketClients.empty())
		return;

	if(isclearmeslist) mes.Clear();

	for(int i=0;i<(int)m_TcpSocketClients.size();i++)
	{
		if(m_TcpSocketClients[i]) m_TcpSocketClients[i]->GetNetMessage(mes,false);
	}	
}

void CTcpSocketClientManager::Sendhtml5(int serverindex,char *Bytes,uint32 len)
{
	if(m_TcpSocketClients.empty())
		return;

	if(serverindex == -1) {
		for(int i=0;i<(int)m_TcpSocketClients.size();i++)
		{
			if(m_TcpSocketClients[i]) m_TcpSocketClients[i]->Sendhtml5(Bytes,len);
		}		
	}
	else {
		if(m_TcpSocketClients[serverindex]) m_TcpSocketClients[serverindex]->Sendhtml5(Bytes,len);
	}	
}

void CTcpSocketClientManager::Update(void)
{
	if(m_TcpSocketClients.empty())
		return;

	for(int i=0;i<(int)m_TcpSocketClients.size();i++)
	{
		if(m_TcpSocketClients[i]) m_TcpSocketClients[i]->Reconnect();
	}	
}

int CTcpSocketClientManager::addTcpSocketClient(CMolTcpSocketClient *pClient)
{
	if(pClient == NULL) return -1;

	m_TcpSocketClients.push_back(pClient);

	return (int)m_TcpSocketClients.size()-1;
}

bool CTcpSocketClientManager::delTcpSocketClient(CMolTcpSocketClient *pClient)
{
	if(pClient == NULL || m_TcpSocketClients.empty()) return false;

	std::vector<CMolTcpSocketClient*>::iterator iter = m_TcpSocketClients.begin();
	for(;iter != m_TcpSocketClients.end();++iter)
	{
		if((*iter) == pClient)
		{
			delete (*iter);
			m_TcpSocketClients.erase(iter);
			return true;
		}
	}

	return false;
}
