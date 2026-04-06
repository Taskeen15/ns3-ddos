#include "tcp-syn-flood-factory.h"
#include "tcp-syn-flood-socket.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/node.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(TcpSynFloodFactory);

TypeId
TcpSynFloodFactory::GetTypeId()
{
  static TypeId tid = TypeId("ns3::TcpSynFloodFactory")
    .SetParent<SocketFactory>()
    .SetGroupName("Internet")
    .AddConstructor<TcpSynFloodFactory>();
  return tid;
}

TcpSynFloodFactory::TcpSynFloodFactory() = default;
TcpSynFloodFactory::~TcpSynFloodFactory() = default;

void TcpSynFloodFactory::SetNode(Ptr<Node> node) { m_node = node; }

Ptr<Socket>
TcpSynFloodFactory::CreateSocket()
{
  Ptr<TcpSynFloodSocket> sock = CreateObject<TcpSynFloodSocket>();
  sock->SetNode(m_node);

  Ptr<TcpL4Protocol> tcp = m_node->GetObject<TcpL4Protocol>();
  sock->SetTcp(tcp);

  return sock;
}

} // namespace ns3
