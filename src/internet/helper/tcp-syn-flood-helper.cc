#include "tcp-syn-flood-helper.h"
#include "ns3/node.h"
#include "ns3/ptr.h"
#include "ns3/object-factory.h"
#include "ns3/tcp-syn-flood-factory.h"

namespace ns3 {

void
TcpSynFloodHelper::Install(Ptr<Node> node) const
{
  ObjectFactory f;
  f.SetTypeId("ns3::TcpSynFloodFactory");
  Ptr<Object> obj = f.Create<Object>();

  Ptr<TcpSynFloodFactory> factory = obj->GetObject<TcpSynFloodFactory>();
  factory->SetNode(node);

  node->AggregateObject(factory);
}

void
TcpSynFloodHelper::Install(NodeContainer nodes) const
{
  for (auto i = nodes.Begin(); i != nodes.End(); ++i)
    Install(*i);
}

} // namespace ns3
