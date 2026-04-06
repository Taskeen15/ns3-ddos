#include "tcp-syn-flood-socket.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/tcp-header.h"
#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/sequence-number.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/random-variable-stream.h"



namespace ns3 {

NS_LOG_COMPONENT_DEFINE("TcpSynFloodSocket");
NS_OBJECT_ENSURE_REGISTERED(TcpSynFloodSocket);

TypeId
TcpSynFloodSocket::GetTypeId()
{
  static TypeId tid = TypeId("ns3::TcpSynFloodSocket")
    .SetParent<Socket>()
    .SetGroupName("Internet")
    .AddConstructor<TcpSynFloodSocket>()
    .AddAttribute("SrcPort",
                  "Random source port generator (ephemeral ports).",
                  StringValue("ns3::UniformRandomVariable[Min=49152|Max=65535]"),
                  MakePointerAccessor(&TcpSynFloodSocket::m_srcPortRv),
                  MakePointerChecker<RandomVariableStream>());
  return tid;
}

TcpSynFloodSocket::TcpSynFloodSocket() = default;
TcpSynFloodSocket::~TcpSynFloodSocket() = default;

void TcpSynFloodSocket::SetTcp(Ptr<TcpL4Protocol> tcp) { m_tcp = tcp; }
void TcpSynFloodSocket::SetNode(Ptr<Node> node) { m_node = node; }


void
TcpSynFloodSocket::SetSpoofedSource(Ipv4Address src)
{
  m_spoofedSrc = src;
}


Ptr<Node>
TcpSynFloodSocket::GetNode() const
{
  return m_node;
}

int
TcpSynFloodSocket::Bind()
{
  // Keep it simple: just mark endpoint setup
  SetupEndpoint();
  return 0;
}

int
TcpSynFloodSocket::Bind(const Address &address)
{
  m_local = address;
  // If user binds to port, remember it
  if (InetSocketAddress::IsMatchingType(address))
  {
    InetSocketAddress isa = InetSocketAddress::ConvertFrom(address);
    m_fixedSrcPort = isa.GetPort();
    m_useFixedSrcPort = true;
  }
  SetupEndpoint();
  return 0;
}

int
TcpSynFloodSocket::Connect(const Address &address)
{
  // NO connection establishment: just remember where to send SYNs
  m_peer = address;
  return 0;
}

int
TcpSynFloodSocket::Close()
{
  return 0;
}

static uint16_t
PickSrcPort(Ptr<RandomVariableStream> rv, bool useFixed, uint16_t fixed)
{
  if (useFixed) return fixed;
  return static_cast<uint16_t>(rv ? rv->GetValue() : 49152);
}

int
TcpSynFloodSocket::Send(Ptr<Packet> p, uint32_t /*flags*/)
{
  if (!m_tcp || !m_node || m_peer.IsInvalid())
    return -1;

  if (p == nullptr)
    p = Create<Packet>(0);


  InetSocketAddress peer = InetSocketAddress::ConvertFrom(m_peer);
  Ipv4Address dst = peer.GetIpv4();
  uint16_t dstPort = peer.GetPort();

  // Pick a source port (random ephemeral unless bound)
  uint16_t srcPort = PickSrcPort(m_srcPortRv, m_useFixedSrcPort, m_fixedSrcPort);

  // // Pick a source IP (first non-loopback interface)
  // Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
  // // interface 0 is loopback; interface 1 is usually the first real one
  // Ipv4Address src = ipv4->GetAddress(1, 0).GetLocal();
    // Pick a source IP
    Ipv4Address src;
    if (m_spoofedSrc != Ipv4Address("0.0.0.0"))
    {
      // spoofed source for classic SYN flood behavior
      src = m_spoofedSrc;
    }
    else
    {
      // real source (first non-loopback interface)
      Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
      src = ipv4->GetAddress(1, 0).GetLocal();
    }


  TcpHeader tcp;
  tcp.SetSourcePort(srcPort);
  tcp.SetDestinationPort(dstPort);
  tcp.SetFlags(TcpHeader::SYN);

  // nice-to-have
  tcp.SetSequenceNumber(SequenceNumber32(1));
  tcp.SetWindowSize(65535);

  // Match ns-3-dev signature you found:
  // SendPacket(packet, header, toAddr, fromAddr, boundNetDevice)
  //m_tcp->SendPacket(p, tcp, dst, src, nullptr);

  Address from = InetSocketAddress(src, srcPort);   // local (source)
  Address to   = InetSocketAddress(dst, dstPort);   // peer  (destination)

  // IMPORTANT: ns-3-dev style is (packet, tcpHeader, localAddr, peerAddr, boundDev)
  m_tcp->SendPacket(p, tcp, from, to, nullptr);


  return p->GetSize();
}


int
TcpSynFloodSocket::SendTo(Ptr<Packet> p, uint32_t flags, const Address &toAddress)
{
  m_peer = toAddress;
  return Send(p, flags);
}

uint32_t TcpSynFloodSocket::GetTxAvailable() const { return 0; }
//int TcpSynFloodSocket::GetErrno() const { return m_errno; }

Socket::SocketErrno
TcpSynFloodSocket::GetErrno() const
{
  return m_errno;
}


void
TcpSynFloodSocket::SetupEndpoint()
{
  // Minimal: do nothing (paper says they reused TCP socket code here).
  // If your build complains about missing endpoint registration, we’ll copy the tiny chunk
  // from TcpSocketBase::SetupEndpoint and paste it here.
}


Socket::SocketType
TcpSynFloodSocket::GetSocketType() const
{
  return Socket::NS3_SOCK_STREAM; // TCP-style socket
}

int TcpSynFloodSocket::Bind6() { return -1; }
int TcpSynFloodSocket::ShutdownSend() { return 0; }
int TcpSynFloodSocket::ShutdownRecv() { return 0; }
int TcpSynFloodSocket::Listen() { return -1; }

uint32_t TcpSynFloodSocket::GetRxAvailable() const { return 0; }

Ptr<Packet>
TcpSynFloodSocket::Recv(uint32_t, uint32_t)
{
  m_errno = SocketErrno::ERROR_AGAIN;
  return nullptr;
}

Ptr<Packet>
TcpSynFloodSocket::RecvFrom(uint32_t, uint32_t, Address& fromAddress)
{
  fromAddress = Address();
  m_errno = SocketErrno::ERROR_AGAIN;
  return nullptr;
}

int
TcpSynFloodSocket::GetSockName(Address& address) const
{
  address = m_local;
  return 0;
}

int
TcpSynFloodSocket::GetPeerName(Address& address) const
{
  address = m_peer;
  return m_peer.IsInvalid() ? -1 : 0;
}

bool
TcpSynFloodSocket::SetAllowBroadcast(bool)
{
  // TCP sockets don't broadcast; but return true to avoid breaking callers
  return true;
}

bool
TcpSynFloodSocket::GetAllowBroadcast() const
{
  return false;
}





} // namespace ns3
