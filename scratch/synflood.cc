// scratch/synflood.cc
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/system-path.h"
#include "ns3/random-variable-stream.h"
#include "ns3/tcp-syn-flood-socket.h"

#include <vector>
#include <sstream>
#include <string>
#include <algorithm>

using namespace ns3;

/*
Topology used in scratch/synflood.cc

 Left side (LAN)                                      Right side (LAN)
 clients:   10.1.1.1  10.1.2.1  10.1.3.1  10.1.4.1     servers: 10.2.1.1  10.2.2.1 ...
 attackers: 10.1.5.1  10.1.6.1                         (TCP PacketSink listening on a few legit service ports)

 Each left host has its own /24 link to Router0:
   10.1.k.0/24  (host = 10.1.k.1, Router0 = 10.1.k.2)   access links: 100 Mbps, 1 ms

 Each right server has its own /24 link to Router1:
   10.2.k.0/24  (server = 10.2.k.1, Router1 = 10.2.k.2) access links: 100 Mbps, 1 ms

 Core bottleneck link between routers:
   10.3.0.0/24  (Router0 = 10.3.0.1, Router1 = 10.3.0.2) bottleneck: 10 Mbps, 10 ms
*/

class SynFloodAttackApp : public Application
{
public:
  SynFloodAttackApp() = default;

  void Setup(const std::vector<Ipv4Address>& serverIps,
             double synPerSecond,
             double firstAttackStartSec,
             double burstDurationSec,
             double burstGapSec,
             uint32_t nBursts,
             uint32_t targetServerIndex,
             bool randomTarget,
             uint16_t attackPortMin,
             uint16_t attackPortMax)
  {
    m_serverIps = serverIps;
    m_rate = synPerSecond;
    m_firstAttackStart = firstAttackStartSec;
    m_burstDuration = burstDurationSec;
    m_burstGap = burstGapSec;
    m_nBursts = nBursts;
    m_targetServerIndex = targetServerIndex;
    m_randomTarget = randomTarget;
    m_attackPortMin = attackPortMin;
    m_attackPortMax = attackPortMax;

    m_pick = CreateObject<UniformRandomVariable>();
    m_pickPort = CreateObject<UniformRandomVariable>();

    if (m_attackPortMin > m_attackPortMax)
    {
      std::swap(m_attackPortMin, m_attackPortMax);
    }
  }

private:
  void StartApplication() override
  {
    m_running = true;
    // small initial delay so the app starts scheduling from time 0
    m_event = Simulator::Schedule(Seconds(0.0), &SynFloodAttackApp::Tick, this);
  }

  void StopApplication() override
  {
    m_running = false;
    if (!m_event.IsExpired())
    {
      m_event.Cancel();
    }
  }

  bool IsAttackTime(double t) const
  {
    if (t < m_firstAttackStart || m_nBursts == 0)
    {
      return false;
    }

    for (uint32_t i = 0; i < m_nBursts; ++i)
    {
      double burstStart = m_firstAttackStart + i * (m_burstDuration + m_burstGap);
      double burstStop  = burstStart + m_burstDuration;

      if (t >= burstStart && t < burstStop)
      {
        return true;
      }
    }
    return false;
  }

  double GetLastBurstEnd() const
  {
    if (m_nBursts == 0)
    {
      return m_firstAttackStart;
    }
    return m_firstAttackStart + (m_nBursts - 1) * (m_burstDuration + m_burstGap) + m_burstDuration;
  }

  void Tick()
  {
    if (!m_running)
    {
      return;
    }

    if (m_serverIps.empty())
    {
      return;
    }

    double now = Simulator::Now().GetSeconds();
    double lastBurstEnd = GetLastBurstEnd();

    if (now >= lastBurstEnd)
    {
      return;
    }

    // If not inside an attack burst, just keep checking periodically.
    if (!IsAttackTime(now))
    {
      m_event = Simulator::Schedule(MilliSeconds(10), &SynFloodAttackApp::Tick, this);
      return;
    }

    uint32_t idx;
    if (m_randomTarget)
    {
      idx = m_pick->GetInteger(0, static_cast<int>(m_serverIps.size()) - 1);
    }
    else
    {
      idx = std::min<uint32_t>(m_targetServerIndex, m_serverIps.size() - 1);
    }

    uint16_t chosenDstPort = static_cast<uint16_t>(
        m_pickPort->GetInteger(m_attackPortMin, m_attackPortMax));

    Address remote = InetSocketAddress(m_serverIps[idx], chosenDstPort);

    Ptr<TcpSynFloodSocket> sock = CreateObject<TcpSynFloodSocket>();
    sock->SetNode(GetNode());
    sock->SetTcp(GetNode()->GetObject<TcpL4Protocol>());

    Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
    Ipv4Address real = ipv4->GetAddress(1, 0).GetLocal();

    // Spoof within same /24 as this attacker, but avoid self and router(.2)
    uint32_t realU = real.Get();
    uint32_t net = realU & 0xFFFFFF00;
    uint8_t realHost = realU & 0xFF;

    uint8_t host;
    do
    {
      host = static_cast<uint8_t>(m_pick->GetInteger(1, 254));
    } while (host == realHost || host == 2);

    Ipv4Address spoof = Ipv4Address(net | host);
    sock->SetSpoofedSource(spoof);

    sock->Connect(remote);
    sock->Send(Create<Packet>(0), 0); // pure SYN
    sock->Close();

    Time interval = Seconds(1.0 / std::max(1e-9, m_rate));
    m_event = Simulator::Schedule(interval, &SynFloodAttackApp::Tick, this);
  }

private:
  bool m_running{false};
  EventId m_event;

  std::vector<Ipv4Address> m_serverIps;
  double m_rate{100.0};

  double m_firstAttackStart{2.0};
  double m_burstDuration{2.0};
  double m_burstGap{5.0};
  uint32_t m_nBursts{6};

  uint32_t m_targetServerIndex{0};
  bool m_randomTarget{false};

  uint16_t m_attackPortMin{1024};
  uint16_t m_attackPortMax{65535};

  Ptr<UniformRandomVariable> m_pick;
  Ptr<UniformRandomVariable> m_pickPort;
};

int
main(int argc, char* argv[])
{
  Time::SetResolution(Time::NS);

  // ---- Defaults ----
  uint32_t nClients   = 50;
  uint32_t nAttackers = 5;
  uint32_t nServers   = 20;

  std::string accessRate = "100Mbps";
  std::string accessDelay = "1ms";
  std::string bottleneckRate = "10Mbps";
  std::string bottleneckDelay = "10ms";

  std::string clientDataRate = "1Mbps";
  uint32_t clientPktSize = 1000;

  double attackRate = 200.0;

  // Paper-style bursty attack defaults
  double firstAttackStart = 2.0;
  double burstDuration = 2.0;
  double burstGap = 5.0;
  uint32_t nBursts = 6;

  // Compute a sim time that covers all bursts plus a little tail
  double simTime = firstAttackStart + nBursts * burstDuration + (nBursts - 1) * burstGap + 3.0;

  // Legit traffic goes to a small fixed set of service ports
  uint16_t legitPortStart = 5000;
  uint32_t nLegitPorts = 3; // 5000, 5001, 5002

  // Attack target server
  uint32_t attackTargetServer = 0;
  bool attackRandomTarget = false;

  // Attack destination ports are randomized per SYN
  uint16_t attackPortMin = 1024;
  uint16_t attackPortMax = 65535;

  std::string pcapDir = "pcap";
  bool enablePcap = true;

  CommandLine cmd;
  cmd.AddValue("nClients", "Number of legitimate clients (left)", nClients);
  cmd.AddValue("nAttackers", "Number of attackers (left)", nAttackers);
  cmd.AddValue("nServers", "Number of servers (right)", nServers);

  cmd.AddValue("accessRate", "Access link data rate", accessRate);
  cmd.AddValue("accessDelay", "Access link delay", accessDelay);
  cmd.AddValue("bottleneckRate", "Bottleneck link data rate", bottleneckRate);
  cmd.AddValue("bottleneckDelay", "Bottleneck link delay", bottleneckDelay);

  cmd.AddValue("clientDataRate", "Legitimate client OnOff data rate", clientDataRate);
  cmd.AddValue("clientPktSize", "Legitimate client packet size", clientPktSize);

  cmd.AddValue("attackRate", "SYN attempts/sec per attacker during attack burst", attackRate);

  cmd.AddValue("firstAttackStart", "Time of first attack burst start (s)", firstAttackStart);
  cmd.AddValue("burstDuration", "Duration of each attack burst (s)", burstDuration);
  cmd.AddValue("burstGap", "Gap between attack bursts (s)", burstGap);
  cmd.AddValue("nBursts", "Number of attack bursts", nBursts);

  cmd.AddValue("simTime", "Simulation time (s)", simTime);

  cmd.AddValue("legitPortStart", "First destination port used by legitimate traffic", legitPortStart);
  cmd.AddValue("nLegitPorts", "Number of destination ports used by legitimate traffic", nLegitPorts);

  cmd.AddValue("attackTargetServer", "Index of server to attack (0-based)", attackTargetServer);
  cmd.AddValue("attackRandomTarget", "If true, attackers pick random victim servers", attackRandomTarget);

  cmd.AddValue("attackPortMin", "Minimum randomized destination port for attack SYNs", attackPortMin);
  cmd.AddValue("attackPortMax", "Maximum randomized destination port for attack SYNs", attackPortMax);

  cmd.AddValue("pcapDir", "PCAP output directory", pcapDir);
  cmd.AddValue("enablePcap", "Enable PCAP capture", enablePcap);

  cmd.Parse(argc, argv);

  if (nServers == 0)
  {
    NS_LOG_UNCOND("nServers must be at least 1");
    return 1;
  }

  if (nLegitPorts == 0)
  {
    NS_LOG_UNCOND("nLegitPorts must be at least 1");
    return 1;
  }

  if (nBursts == 0)
  {
    NS_LOG_UNCOND("nBursts must be at least 1");
    return 1;
  }

  std::vector<uint16_t> legitPorts;
  legitPorts.reserve(nLegitPorts);
  for (uint32_t i = 0; i < nLegitPorts; ++i)
  {
    legitPorts.push_back(static_cast<uint16_t>(legitPortStart + i));
  }

  // ---- Nodes ----
  NodeContainer clients;
  clients.Create(nClients);

  NodeContainer attackers;
  attackers.Create(nAttackers);

  NodeContainer servers;
  servers.Create(nServers);

  NodeContainer routers;
  routers.Create(2);

  InternetStackHelper internet;
  internet.Install(clients);
  internet.Install(attackers);
  internet.Install(servers);
  internet.Install(routers);

  // ---- Links ----
  PointToPointHelper access;
  access.SetDeviceAttribute("DataRate", StringValue(accessRate));
  access.SetChannelAttribute("Delay", StringValue(accessDelay));

  PointToPointHelper bottleneck;
  bottleneck.SetDeviceAttribute("DataRate", StringValue(bottleneckRate));
  bottleneck.SetChannelAttribute("Delay", StringValue(bottleneckDelay));

  std::vector<NetDeviceContainer> leftDevs;
  leftDevs.reserve(nClients + nAttackers);

  for (uint32_t i = 0; i < clients.GetN(); i++)
  {
    leftDevs.push_back(access.Install(clients.Get(i), routers.Get(0)));
  }

  for (uint32_t i = 0; i < attackers.GetN(); i++)
  {
    leftDevs.push_back(access.Install(attackers.Get(i), routers.Get(0)));
  }

  std::vector<NetDeviceContainer> rightDevs;
  rightDevs.reserve(nServers);

  for (uint32_t i = 0; i < servers.GetN(); i++)
  {
    rightDevs.push_back(access.Install(servers.Get(i), routers.Get(1)));
  }

  NetDeviceContainer coreDevs = bottleneck.Install(routers.Get(0), routers.Get(1));

  // ---- IP addressing ----
  Ipv4AddressHelper addr;

  std::vector<Ipv4InterfaceContainer> leftIfs;
  for (uint32_t i = 0; i < leftDevs.size(); i++)
  {
    std::ostringstream subnet;
    subnet << "10.1." << (i + 1) << ".0";
    addr.SetBase(subnet.str().c_str(), "255.255.255.0");
    leftIfs.push_back(addr.Assign(leftDevs[i]));
  }

  std::vector<Ipv4InterfaceContainer> rightIfs;
  for (uint32_t i = 0; i < rightDevs.size(); i++)
  {
    std::ostringstream subnet;
    subnet << "10.2." << (i + 1) << ".0";
    addr.SetBase(subnet.str().c_str(), "255.255.255.0");
    rightIfs.push_back(addr.Assign(rightDevs[i]));
  }

  addr.SetBase("10.3.0.0", "255.255.255.0");
  addr.Assign(coreDevs);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // ---- Servers: install sinks only on legitimate service ports ----
  ApplicationContainer sinkApps;
  for (uint32_t s = 0; s < servers.GetN(); s++)
  {
    for (uint16_t p : legitPorts)
    {
      PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                  InetSocketAddress(Ipv4Address::GetAny(), p));
      sinkApps.Add(sinkHelper.Install(servers.Get(s)));
    }
  }

  sinkApps.Start(Seconds(0.0));
  sinkApps.Stop(Seconds(simTime));

  // ---- Legit traffic ----
  Ptr<UniformRandomVariable> pickServer = CreateObject<UniformRandomVariable>();
  Ptr<UniformRandomVariable> pickPort = CreateObject<UniformRandomVariable>();

  for (uint32_t c = 0; c < clients.GetN(); c++)
  {
    uint32_t s = pickServer->GetInteger(0, static_cast<int>(servers.GetN()) - 1);
    uint32_t pIdx = pickPort->GetInteger(0, static_cast<int>(legitPorts.size()) - 1);

    Address remote = InetSocketAddress(rightIfs[s].GetAddress(0), legitPorts[pIdx]);

    OnOffHelper onoff("ns3::TcpSocketFactory", remote);
    onoff.SetAttribute("DataRate", StringValue(clientDataRate));
    onoff.SetAttribute("PacketSize", UintegerValue(clientPktSize));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app = onoff.Install(clients.Get(c));
    app.Start(Seconds(1.0 + 0.02 * c));
    app.Stop(Seconds(simTime - 1.0));
  }

  // ---- Attack target IPs ----
  std::vector<Ipv4Address> serverIps;
  serverIps.reserve(servers.GetN());
  for (uint32_t s = 0; s < servers.GetN(); s++)
  {
    serverIps.push_back(rightIfs[s].GetAddress(0));
  }

  // ---- Attackers ----
  for (uint32_t a = 0; a < attackers.GetN(); a++)
  {
    Ptr<SynFloodAttackApp> app = CreateObject<SynFloodAttackApp>();
    app->Setup(serverIps,
               attackRate,
               firstAttackStart,
               burstDuration,
               burstGap,
               nBursts,
               attackTargetServer,
               attackRandomTarget,
               attackPortMin,
               attackPortMax);

    attackers.Get(a)->AddApplication(app);
    app->SetStartTime(Seconds(0.0));
    app->SetStopTime(Seconds(simTime));
  }

  // ---- PCAP ----
  if (enablePcap)
  {
    SystemPath::MakeDirectories(pcapDir);
    bottleneck.EnablePcap(pcapDir + "/synflood_core_r0", coreDevs.Get(0), true);
    bottleneck.EnablePcap(pcapDir + "/synflood_core_r1", coreDevs.Get(1), true);
  }

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();
  return 0;
}