/************************************************************************************
* Copyright (C) 2017                                                               *
* TETCOS, Bangalore. India                                                         *
*                                                                                  *
* Tetcos owns the intellectual property rights in the Product and its content.     *
* The copying, redistribution, reselling or publication of any or all of the       *
* Product or its content without express prior written consent of Tetcos is        *
* prohibited. Ownership and / or any other right relating to the software and all  *
* intellectual property rights therein shall remain at all times with Tetcos.      *
*                                                                                  *
* Author:    Soniya                                                                *
*                                                                                  *
* ---------------------------------------------------------------------------------*/

#include "main.h"
#include "TCP.h"
#include "List.h"
#include "TCP_Header.h"
#include "TCP_Enum.h"

int malicious_node[NUMBEROFMALICIOUSNODE] = { 2, 6 };
static void send_syn_packet(PNETSIM_SOCKET s);
//static PNETSIM_SOCKET socket_creation();
int target_node = 4;
PNETSIM_SOCKET get_Remotesocket(NETSIM_ID d, PSOCKETADDRESS addr);
static PSOCKETADDRESS sockAddr = NULL;

int is_malicious_node(NETSIM_ID devid)
{
	for (int i = 0; i < NUMBEROFMALICIOUSNODE; i++)
		if (devid == malicious_node[i]) return 1;

	return 0;
}

void syn_flood()
{
	/*
		if (!sockAddr)
		{
			sockAddr = calloc(1, sizeof * sockAddr);
			sockAddr->ip = DEVICE_NWADDRESS(target_node, 1);

		}

		PNETSIM_SOCKET s = get_Remotesocket(malicious_node, sockAddr);
*/
		extern PSOCKETADDRESS anySocketAddr;
		anySocketAddr->ip = DEVICE_NWADDRESS(target_node, 1);
		PNETSIM_SOCKET s = get_Remotesocket(pstruEventDetails->nDeviceId, anySocketAddr);
		ptrSOCKETINTERFACE sId = (ptrSOCKETINTERFACE)pstruEventDetails->szOtherDetails;
		NetSim_EVENTDETAILS pevent;
		if (!s)
		{
			s = socket_creation();
			tcp_connect(s, s->localAddr, s->remoteAddr);
		}
	
		else
		{
			s->localDeviceId = pstruEventDetails->nDeviceId;
			s->remoteDeviceId = target_node;
			s->sId = sId;
			send_syn_packet(s);
			memcpy(&pevent, pstruEventDetails, sizeof pevent);
			pevent.dEventTime = pstruEventDetails->dEventTime + 1000;
			pevent.nDeviceId = pstruEventDetails->nDeviceId;
			pevent.nPacketId = 0;
			pevent.nEventType = TIMER_EVENT;
			pevent.nProtocolId = TX_PROTOCOL_TCP;
			pevent.nSubEventType = SYN_FLOOD;
			fnpAddEvent(&pevent);
		}
	

}

static void send_syn_packet(PNETSIM_SOCKET s)
{
	NetSim_PACKET* syn = create_syn(s, pstruEventDetails->dEventTime);

	s->tcb->SND.UNA = s->tcb->ISS;
	s->tcb->SND.NXT = s->tcb->ISS + 1;
	tcp_change_state(s, TCPCONNECTION_SYN_SENT);

	s->tcb->synRetries++;

	s->tcpMetrics->synSent++;

	send_to_network(syn, s);
	add_timeout_event(s, syn);
}

/*static PNETSIM_SOCKET */ int socket_creation()
{
	static int s_id = 100;
	ptrSOCKETINTERFACE sId = (ptrSOCKETINTERFACE)pstruEventDetails->szOtherDetails;
	PNETSIM_SOCKET newSocket = tcp_create_socket();

	add_to_socket_list(pstruEventDetails->nDeviceId, newSocket);

	PSOCKETADDRESS localsocketAddr = (PSOCKETADDRESS)calloc(1, sizeof * localsocketAddr);
	localsocketAddr->ip = DEVICE_NWADDRESS(pstruEventDetails->nDeviceId, 1);
	localsocketAddr->port = 0;

	PSOCKETADDRESS remotesocketAddr = (PSOCKETADDRESS)calloc(1, sizeof * remotesocketAddr);
	remotesocketAddr->ip = DEVICE_NWADDRESS(target_node, 1);
	remotesocketAddr->port = 0;

	newSocket->SocketId = s_id;
	s_id++;

	newSocket->localAddr = localsocketAddr;
	newSocket->remoteAddr = remotesocketAddr;

	newSocket->localDeviceId = pstruEventDetails->nDeviceId;
	newSocket->remoteDeviceId = target_node;

	newSocket->sId = sId;

	return newSocket;
}
