#pragma once
#include "ns3/node-container.h"

namespace ns3 {

class TcpSynFloodHelper
{
public:
  void Install(NodeContainer nodes) const;
  void Install(Ptr<Node> node) const;
};

} // namespace ns3
