#pragma once
#include "ns3/socket-factory.h"
#include "ns3/ptr.h"
#include "ns3/node.h"

namespace ns3 {
class Node;

class TcpL4Protocol;
class TcpSynFloodFactory : public SocketFactory
{
public:
  static TypeId GetTypeId();
  TcpSynFloodFactory();
  ~TcpSynFloodFactory() override;

  Ptr<Socket> CreateSocket() override;

  void SetNode(Ptr<Node> node);

private:
  Ptr<Node> m_node;
};

} // namespace ns3
