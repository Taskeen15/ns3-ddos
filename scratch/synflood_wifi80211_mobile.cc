// scratch/synflood_wifi80211_mobile.cc
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/system-path.h"
#include "ns3/random-variable-stream.h"
#include "ns3/tcp-syn-flood-socket.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/yans-wifi-helper.h"

#include <vector>
#include <sstream>
#include <string>
#include <algorithm>

using namespace ns3;

/*
Wireless 802.11 (mobile) version of synflood.cc

Topology:

  Left WLAN (mobile STAs)                         Right WLAN (mobile STAs)
  ---------------------------------------------------------------
  clients + attackers  <~~~wifi~~~>  AP/Router0 ---- p2p ---- AP/Router1  <~~~wifi~~~> servers

  - Left side: legitimate clients + attackers are Wi-Fi stations and move.
  - Right side: servers are Wi-Fi stations and move.
  - AP/Router0 and AP/Router1 are static access points and also act as IP routers.
  - Core p2p link is kept exactly like the wired version so output PCAP/entropy workflow stays similar.

  Subnets:
    Left WLAN   : 10.1.0.0/24
    Core link   : 10.2.0.0/24
    Right WLAN  : 10.3.0.0/24
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
    return m_firstAttackStart +
           (m_nBursts - 1) * (m_burstDuration + m_burstGap) +
           m_burstDuration;
  }

  void Tick()
  {
    if (!m_running || m_serverIps.empty())
    {
      return;
    }

    double now = Simulator::Now().GetSeconds();
    double lastBurstEnd = GetLastBurstEnd();

    if (now >= lastBurstEnd)
    {
      return;
    }

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

    // Use first non-loopback interface as "real" IP, then spoof another host
    // inside the same /24 just like the wired version did conceptually.
    Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
    Ipv4Address real = ipv4->GetAddress(1, 0).GetLocal();

    uint32_t realU = real.Get();
    uint32_t net = realU & 0xFFFFFF00;
    uint8_t realHost = realU & 0xFF;

    uint8_t host;
    do
    {
      host = static_cast<uint8_t>(m_pick->GetInteger(1, 254));
    } while (host == realHost);

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

  // -----------------------------
  // Same traffic defaults as wired version
  // -----------------------------
  uint32_t nClients   = 50;
  uint32_t nAttackers = 5;
  uint32_t nServers   = 20;

  std::string bottleneckRate = "10Mbps";
  std::string bottleneckDelay = "10ms";

  std::string clientDataRate = "1Mbps";
  uint32_t clientPktSize = 1000;

  double attackRate = 200.0;

  double firstAttackStart = 2.0;
  double burstDuration = 2.0;
  double burstGap = 5.0;
  uint32_t nBursts = 6;

  double simTime = firstAttackStart +
                   nBursts * burstDuration +
                   (nBursts - 1) * burstGap + 3.0;

  uint16_t legitPortStart = 5000;
  uint32_t nLegitPorts = 3;

  uint32_t attackTargetServer = 0;
  bool attackRandomTarget = false;

  uint16_t attackPortMin = 1024;
  uint16_t attackPortMax = 65535;

  // -----------------------------
  // Wi-Fi / mobility parameters
  // -----------------------------
  std::string wifiPhyMode = "HtMcs7";
  double leftArea = 60.0;   // square area for left WLAN stations
  double rightArea = 60.0;  // square area for right WLAN stations
  double mobilitySpeedMin = 1.0;
  double mobilitySpeedMax = 3.0;
  double mobilityPause = 0.2;

  std::string pcapDir = "results/wifi80211_mobile/test_pcap";
  bool enablePcap = true;

  CommandLine cmd(__FILE__);
  cmd.AddValue("nClients", "Number of legitimate clients (left WLAN)", nClients);
  cmd.AddValue("nAttackers", "Number of attackers (left WLAN)", nAttackers);
  cmd.AddValue("nServers", "Number of servers (right WLAN)", nServers);

  cmd.AddValue("bottleneckRate", "Core bottleneck data rate", bottleneckRate);
  cmd.AddValue("bottleneckDelay", "Core bottleneck delay", bottleneckDelay);

  cmd.AddValue("clientDataRate", "Legitimate client OnOff data rate", clientDataRate);
  cmd.AddValue("clientPktSize", "Legitimate client packet size", clientPktSize);

  cmd.AddValue("attackRate", "SYN attempts/sec per attacker during burst", attackRate);

  cmd.AddValue("firstAttackStart", "Time of first attack burst start (s)", firstAttackStart);
  cmd.AddValue("burstDuration", "Duration of each attack burst (s)", burstDuration);
  cmd.AddValue("burstGap", "Gap between attack bursts (s)", burstGap);
  cmd.AddValue("nBursts", "Number of attack bursts", nBursts);

  cmd.AddValue("simTime", "Simulation time (s)", simTime);

  cmd.AddValue("legitPortStart", "First destination port used by legitimate traffic", legitPortStart);
  cmd.AddValue("nLegitPorts", "Number of legitimate service ports", nLegitPorts);

  cmd.AddValue("attackTargetServer", "Index of server to attack (0-based)", attackTargetServer);
  cmd.AddValue("attackRandomTarget", "If true, attackers choose random victim servers", attackRandomTarget);

  cmd.AddValue("attackPortMin", "Minimum randomized destination port for attack SYNs", attackPortMin);
  cmd.AddValue("attackPortMax", "Maximum randomized destination port for attack SYNs", attackPortMax);

  cmd.AddValue("wifiPhyMode", "Wi-Fi data mode", wifiPhyMode);
  cmd.AddValue("leftArea", "Side length of left WLAN mobility area (meters)", leftArea);
  cmd.AddValue("rightArea", "Side length of right WLAN mobility area (meters)", rightArea);
  cmd.AddValue("mobilitySpeedMin", "Minimum station movement speed (m/s)", mobilitySpeedMin);
  cmd.AddValue("mobilitySpeedMax", "Maximum station movement speed (m/s)", mobilitySpeedMax);
  cmd.AddValue("mobilityPause", "Pause time for random-walk mobility (s)", mobilityPause);

  cmd.AddValue("pcapDir", "PCAP output directory", pcapDir);
  cmd.AddValue("enablePcap", "Enable PCAP capture", enablePcap);

  cmd.Parse(argc, argv);

  if (nServers == 0 || nLegitPorts == 0 || nBursts == 0)
  {
    NS_LOG_UNCOND("nServers, nLegitPorts, and nBursts must all be at least 1");
    return 1;
  }

  std::vector<uint16_t> legitPorts;
  legitPorts.reserve(nLegitPorts);
  for (uint32_t i = 0; i < nLegitPorts; ++i)
  {
    legitPorts.push_back(static_cast<uint16_t>(legitPortStart + i));
  }

  // -----------------------------
  // Nodes
  // -----------------------------
  NodeContainer clients;
  clients.Create(nClients);

  NodeContainer attackers;
  attackers.Create(nAttackers);

  NodeContainer servers;
  servers.Create(nServers);

  NodeContainer apLeft;
  apLeft.Create(1);

  NodeContainer apRight;
  apRight.Create(1);

  NodeContainer leftStas;
  for (uint32_t i = 0; i < nClients; ++i)
  {
    leftStas.Add(clients.Get(i));
  }
  for (uint32_t i = 0; i < nAttackers; ++i)
  {
    leftStas.Add(attackers.Get(i));
  }

  NodeContainer rightStas;
  rightStas.Add(servers);

  InternetStackHelper internet;
  internet.Install(clients);
  internet.Install(attackers);
  internet.Install(servers);
  internet.Install(apLeft);
  internet.Install(apRight);

  // -----------------------------
  // Mobility
  // -----------------------------
  MobilityHelper leftApMobility;
  Ptr<ListPositionAllocator> leftApPos = CreateObject<ListPositionAllocator>();
  leftApPos->Add(Vector(leftArea / 2.0, leftArea / 2.0, 0.0));
  leftApMobility.SetPositionAllocator(leftApPos);
  leftApMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  leftApMobility.Install(apLeft);

  MobilityHelper rightApMobility;
  Ptr<ListPositionAllocator> rightApPos = CreateObject<ListPositionAllocator>();
  rightApPos->Add(Vector(rightArea / 2.0, rightArea / 2.0, 0.0));
  rightApMobility.SetPositionAllocator(rightApPos);
  rightApMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  rightApMobility.Install(apRight);

  MobilityHelper leftStaMobility;
  leftStaMobility.SetPositionAllocator(
      "ns3::RandomRectanglePositionAllocator",
      "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(leftArea) + "]"),
      "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(leftArea) + "]"));

  leftStaMobility.SetMobilityModel(
    "ns3::RandomWalk2dMobilityModel",
    "Bounds", RectangleValue(Rectangle(0.0, leftArea, 0.0, leftArea)),
    "Speed", StringValue("ns3::UniformRandomVariable[Min=" +
                         std::to_string(mobilitySpeedMin) +
                         "|Max=" + std::to_string(mobilitySpeedMax) + "]"),
    "Distance", DoubleValue(8.0));

  leftStaMobility.Install(leftStas);

  MobilityHelper rightStaMobility;
  rightStaMobility.SetPositionAllocator(
      "ns3::RandomRectanglePositionAllocator",
      "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(rightArea) + "]"),
      "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(rightArea) + "]"));

 rightStaMobility.SetMobilityModel(
    "ns3::RandomWalk2dMobilityModel",
    "Bounds", RectangleValue(Rectangle(0.0, rightArea, 0.0, rightArea)),
    "Speed", StringValue("ns3::UniformRandomVariable[Min=" +
                         std::to_string(mobilitySpeedMin) +
                         "|Max=" + std::to_string(mobilitySpeedMax) + "]"),
    "Distance", DoubleValue(8.0));


  rightStaMobility.Install(rightStas);

  // -----------------------------
  // Left Wi-Fi (clients + attackers)
  // -----------------------------
YansWifiChannelHelper leftChannel = YansWifiChannelHelper::Default();
YansWifiPhyHelper leftPhy;
leftPhy.SetChannel(leftChannel.Create());
leftPhy.Set("ChannelSettings", StringValue("{1, 20, BAND_2_4GHZ, 0}"));

WifiHelper leftWifi;
leftWifi.SetStandard(WIFI_STANDARD_80211n);
leftWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("HtMcs7"),
                                 "ControlMode", StringValue("HtMcs0"));

WifiMacHelper leftMac;
Ssid leftSsid = Ssid("left-wlan");

leftMac.SetType("ns3::StaWifiMac",
                "Ssid", SsidValue(leftSsid),
                "ActiveProbing", BooleanValue(false));
NetDeviceContainer leftStaDevices = leftWifi.Install(leftPhy, leftMac, leftStas);

leftMac.SetType("ns3::ApWifiMac",
                "Ssid", SsidValue(leftSsid));
NetDeviceContainer leftApDevice = leftWifi.Install(leftPhy, leftMac, apLeft);


// Right WLAN
YansWifiChannelHelper rightChannel = YansWifiChannelHelper::Default();
YansWifiPhyHelper rightPhy;
rightPhy.SetChannel(rightChannel.Create());
rightPhy.Set("ChannelSettings", StringValue("{6, 20, BAND_2_4GHZ, 0}"));

WifiHelper rightWifi;
rightWifi.SetStandard(WIFI_STANDARD_80211n);
rightWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                  "DataMode", StringValue("HtMcs7"),
                                  "ControlMode", StringValue("HtMcs0"));

WifiMacHelper rightMac;
Ssid rightSsid = Ssid("right-wlan");

rightMac.SetType("ns3::StaWifiMac",
                 "Ssid", SsidValue(rightSsid),
                 "ActiveProbing", BooleanValue(false));
NetDeviceContainer rightStaDevices = rightWifi.Install(rightPhy, rightMac, rightStas);

rightMac.SetType("ns3::ApWifiMac",
                 "Ssid", SsidValue(rightSsid));
NetDeviceContainer rightApDevice = rightWifi.Install(rightPhy, rightMac, apRight);




  // -----------------------------
  // Core bottleneck
  // -----------------------------
  PointToPointHelper bottleneck;
  bottleneck.SetDeviceAttribute("DataRate", StringValue(bottleneckRate));
  bottleneck.SetChannelAttribute("Delay", StringValue(bottleneckDelay));
  NetDeviceContainer coreDevs = bottleneck.Install(apLeft.Get(0), apRight.Get(0));

  // -----------------------------
  // IP addressing
  // -----------------------------
  Ipv4AddressHelper addr;

  addr.SetBase("10.1.0.0", "255.255.255.0");
  Ipv4InterfaceContainer leftStaIfs = addr.Assign(leftStaDevices);
  Ipv4InterfaceContainer leftApIf = addr.Assign(leftApDevice);

  addr.SetBase("10.2.0.0", "255.255.255.0");
  Ipv4InterfaceContainer coreIfs = addr.Assign(coreDevs);

  addr.SetBase("10.3.0.0", "255.255.255.0");
  Ipv4InterfaceContainer rightStaIfs = addr.Assign(rightStaDevices);
  Ipv4InterfaceContainer rightApIf = addr.Assign(rightApDevice);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // -----------------------------
  // Servers: sinks on legit service ports
  // -----------------------------
  ApplicationContainer sinkApps;
  for (uint32_t s = 0; s < servers.GetN(); ++s)
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

  // -----------------------------
  // Legitimate TCP traffic
  // -----------------------------
  Ptr<UniformRandomVariable> pickServer = CreateObject<UniformRandomVariable>();
  Ptr<UniformRandomVariable> pickPort = CreateObject<UniformRandomVariable>();

  for (uint32_t c = 0; c < clients.GetN(); ++c)
  {
    uint32_t s = pickServer->GetInteger(0, static_cast<int>(servers.GetN()) - 1);
    uint32_t pIdx = pickPort->GetInteger(0, static_cast<int>(legitPorts.size()) - 1);

    Address remote = InetSocketAddress(rightStaIfs.GetAddress(s), legitPorts[pIdx]);

    OnOffHelper onoff("ns3::TcpSocketFactory", remote);
    onoff.SetAttribute("DataRate", StringValue(clientDataRate));
    onoff.SetAttribute("PacketSize", UintegerValue(clientPktSize));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app = onoff.Install(clients.Get(c));
    app.Start(Seconds(1.0 + 0.02 * c));
    app.Stop(Seconds(simTime - 1.0));
  }

  // -----------------------------
  // Attack target IP list
  // -----------------------------
  std::vector<Ipv4Address> serverIps;
  serverIps.reserve(servers.GetN());
  for (uint32_t s = 0; s < servers.GetN(); ++s)
  {
    serverIps.push_back(rightStaIfs.GetAddress(s));
  }

  // -----------------------------
  // Attackers
  // -----------------------------
  for (uint32_t a = 0; a < attackers.GetN(); ++a)
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

  // -----------------------------
  // PCAP
  // -----------------------------
  if (enablePcap)
  {
    SystemPath::MakeDirectories(pcapDir);

    // Core bottleneck PCAPs: closest equivalent to wired experiment output
    bottleneck.EnablePcap(pcapDir + "/wifi80211_mobile_core_left", coreDevs.Get(0), true);
    bottleneck.EnablePcap(pcapDir + "/wifi80211_mobile_core_right", coreDevs.Get(1), true);

    // Optional Wi-Fi side captures too
    leftPhy.EnablePcap(pcapDir + "/wifi80211_mobile_left_ap", leftApDevice.Get(0), true);
    rightPhy.EnablePcap(pcapDir + "/wifi80211_mobile_right_ap", rightApDevice.Get(0), true);
  }

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();
  return 0;
}