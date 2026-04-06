#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/system-path.h"
#include "ns3/traffic-control-module.h"
#include "ns3/ppp-header.h"
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>

using namespace ns3;


NS_LOG_COMPONENT_DEFINE("IcmpFloodDdosExample");


static uint64_t g_icmpBytesSinceLastSample = 0;

static void
VictimMacRxTrace(Ptr<const Packet> packet)
{
  if (!packet)
  {
    return;
  }

  Ptr<Packet> copy = packet->Copy();

  if (copy->GetSize() == 0)
  {
    return;
  }

  PppHeader ppp;
  if (copy->GetSize() >= ppp.GetSerializedSize())
  {
    copy->RemoveHeader(ppp);
    // 0x0021 = IPv4
    if (ppp.GetProtocol() != 0x0021)
    {
      return;
    }
  }

  if (copy->GetSize() == 0)
  {
    return;
  }

  Ipv4Header ip;
  copy->RemoveHeader(ip);
  if (ip.GetProtocol() != 1) // ICMP
  {
    return;
  }

  if (copy->GetSize() == 0)
  {
    return;
  }

  Icmpv4Header icmp;
  copy->RemoveHeader(icmp);
  if (icmp.GetType() == Icmpv4Header::ICMPV4_ECHO)
  {
    g_icmpBytesSinceLastSample += packet->GetSize();
  }
}

struct MetricsState
{
  std::ofstream throughputCsv;
  std::ofstream queueCsv;
  std::ofstream dropsCsv;

  Ptr<PacketSink> legitSink;
  Ptr<QueueDisc> rootQdisc;

  double sampleInterval{0.1};
  double attackStart{6.0};
  double attackStop{14.0};
  double simStop{20.0};

  uint64_t lastLegitBytes{0};
  uint64_t lastDropPackets{0};
  uint32_t maxQdiscPackets{0};

  double sumLegitPre{0.0};
  double sumLegitDuring{0.0};
  double sumLegitPost{0.0};
  double sumIcmpPre{0.0};
  double sumIcmpDuring{0.0};
  double sumIcmpPost{0.0};
  double sumQueuePre{0.0};
  double sumQueueDuring{0.0};
  double sumQueuePost{0.0};
  uint32_t nPre{0};
  uint32_t nDuring{0};
  uint32_t nPost{0};
};

static std::string
PhaseOf(double t, double attackStart, double attackStop)
{
  if (t < attackStart)
  {
    return "pre";
  }
  if (t <= attackStop)
  {
    return "during";
  }
  return "post";
}

static void
SampleMetrics(MetricsState* s)
{
  const double now = Simulator::Now().GetSeconds();
  const double dt = s->sampleInterval;

  uint64_t legitNow = s->legitSink->GetTotalRx();
  uint64_t legitDelta = legitNow - s->lastLegitBytes;
  s->lastLegitBytes = legitNow;
  double legitMbps = (legitDelta * 8.0) / (dt * 1e6);

  uint64_t icmpBytes = g_icmpBytesSinceLastSample;
  g_icmpBytesSinceLastSample = 0;
  double icmpMbps = (icmpBytes * 8.0) / (dt * 1e6);

  uint32_t qPkts = s->rootQdisc->GetNPackets();
  s->maxQdiscPackets = std::max(s->maxQdiscPackets, qPkts);

  QueueDisc::Stats stats = s->rootQdisc->GetStats();
  uint64_t dropsTotal = stats.nTotalDroppedPackets;
  uint64_t dropsDelta = dropsTotal - s->lastDropPackets;
  s->lastDropPackets = dropsTotal;

  std::string phase = PhaseOf(now, s->attackStart, s->attackStop);

  s->throughputCsv << std::fixed << std::setprecision(3)
                   << now << "," << legitMbps << "," << icmpMbps << "," << phase << "\n";

  s->queueCsv << std::fixed << std::setprecision(3)
              << now << "," << qPkts << "," << phase << "\n";

  s->dropsCsv << std::fixed << std::setprecision(3)
              << now << "," << dropsDelta << "," << dropsTotal << "," << phase << "\n";

  if (phase == "pre")
  {
    s->sumLegitPre += legitMbps;
    s->sumIcmpPre += icmpMbps;
    s->sumQueuePre += qPkts;
    s->nPre++;
  }
  else if (phase == "during")
  {
    s->sumLegitDuring += legitMbps;
    s->sumIcmpDuring += icmpMbps;
    s->sumQueueDuring += qPkts;
    s->nDuring++;
  }
  else
  {
    s->sumLegitPost += legitMbps;
    s->sumIcmpPost += icmpMbps;
    s->sumQueuePost += qPkts;
    s->nPost++;
  }

  if (now + dt <= s->simStop + 1e-9)
  {
    Simulator::Schedule(Seconds(dt), &SampleMetrics, s);
  }
}

static double
Avg(double sum, uint32_t n)
{
  return (n == 0) ? 0.0 : (sum / static_cast<double>(n));
}

int
main(int argc, char* argv[])
{
  Time::SetResolution(Time::NS);

  uint32_t nLegitClients = 3;
  uint32_t nAttackers = 10;

  std::string accessRate = "100Mbps";
  std::string accessDelay = "1ms";
  std::string bottleneckRate = "10Mbps";
  std::string bottleneckDelay = "10ms";

  double attackStart = 6.0;
  double attackStop = 14.0;
  double simStop = 20.0;
  double sampleInterval = 0.1;

  std::string legitTcpType = "ns3::TcpNewReno";
  std::string legitDataRate = "6Mbps";
  uint32_t legitSendSize = 1200;
  uint16_t legitPort = 5000;

  double icmpPpsPerAttacker = 700.0;
  uint32_t icmpPayloadSize = 512;
  double attackStartJitterMax = 0.20;
  double attackRateJitterFrac = 0.05;

  std::string outputDir = "results/icmp-flood";
  bool enablePcap = true;
  bool enableFlowMonitor = true;

  CommandLine cmd(__FILE__);
  cmd.AddValue("nLegitClients", "Number of legitimate TCP senders", nLegitClients);
  cmd.AddValue("nAttackers", "Number of ICMP attackers", nAttackers);
  cmd.AddValue("accessRate", "Access link rate", accessRate);
  cmd.AddValue("accessDelay", "Access link delay", accessDelay);
  cmd.AddValue("bottleneckRate", "Bottleneck link rate", bottleneckRate);
  cmd.AddValue("bottleneckDelay", "Bottleneck link delay", bottleneckDelay);
  cmd.AddValue("attackStart", "Attack start time in seconds", attackStart);
  cmd.AddValue("attackStop", "Attack stop time in seconds", attackStop);
  cmd.AddValue("simStop", "Simulation stop time in seconds", simStop);
  cmd.AddValue("sampleInterval", "Metrics sampling interval in seconds", sampleInterval);
  cmd.AddValue("legitTcpType", "Transport for legitimate TCP flows", legitTcpType);
  cmd.AddValue("legitDataRate", "Application data rate per legitimate sender", legitDataRate);
  cmd.AddValue("legitSendSize", "BulkSend send size in bytes", legitSendSize);
  cmd.AddValue("legitPort", "Victim TCP port for legitimate traffic", legitPort);
  cmd.AddValue("icmpPpsPerAttacker", "ICMP Echo Request rate per attacker (pps)", icmpPpsPerAttacker);
  cmd.AddValue("icmpPayloadSize", "ICMP payload bytes", icmpPayloadSize);
  cmd.AddValue("attackStartJitterMax", "Max random start jitter in seconds for each attacker", attackStartJitterMax);
  cmd.AddValue("attackRateJitterFrac", "Unused placeholder for consistency with the spec", attackRateJitterFrac);
  cmd.AddValue("outputDir", "Directory where CSV, XML, and PCAP files are written", outputDir);
  cmd.AddValue("enablePcap", "Enable PCAP capture", enablePcap);
  cmd.AddValue("enableFlowMonitor", "Enable FlowMonitor XML export", enableFlowMonitor);
  cmd.Parse(argc, argv);

  Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TypeId::LookupByName(legitTcpType)));

  SystemPath::MakeDirectories(outputDir);
  SystemPath::MakeDirectories(outputDir + "/pcap");

  NodeContainer legitClients;
  legitClients.Create(nLegitClients);
  NodeContainer attackers;
  attackers.Create(nAttackers);
  NodeContainer routers;
  routers.Create(1);
  NodeContainer victim;
  victim.Create(1);

  InternetStackHelper internet;
  internet.Install(legitClients);
  internet.Install(attackers);
  internet.Install(routers);
  internet.Install(victim);

  PointToPointHelper access;
  access.SetDeviceAttribute("DataRate", StringValue(accessRate));
  access.SetChannelAttribute("Delay", StringValue(accessDelay));

  PointToPointHelper bottleneck;
  bottleneck.SetDeviceAttribute("DataRate", StringValue(bottleneckRate));
  bottleneck.SetChannelAttribute("Delay", StringValue(bottleneckDelay));

  std::vector<NetDeviceContainer> leftLinks;
  leftLinks.reserve(nLegitClients + nAttackers);

  for (uint32_t i = 0; i < legitClients.GetN(); ++i)
  {
    leftLinks.push_back(access.Install(legitClients.Get(i), routers.Get(0)));
  }
  for (uint32_t i = 0; i < attackers.GetN(); ++i)
  {
    leftLinks.push_back(access.Install(attackers.Get(i), routers.Get(0)));
  }

  NetDeviceContainer bottleneckDevs = bottleneck.Install(routers.Get(0), victim.Get(0));

  Ipv4AddressHelper addr;
  std::vector<Ipv4InterfaceContainer> leftIfs;
  for (uint32_t i = 0; i < leftLinks.size(); ++i)
  {
    std::ostringstream subnet;
    subnet << "10.1." << (i + 1) << ".0";
    addr.SetBase(subnet.str().c_str(), "255.255.255.0");
    leftIfs.push_back(addr.Assign(leftLinks[i]));
  }

  addr.SetBase("10.2.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bottleneckIfs = addr.Assign(bottleneckDevs);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

 TrafficControlHelper tch;

  // remove any existing root qdisc first
  tch.Uninstall(bottleneckDevs.Get(0));

  //tch.SetRootQueueDisc("ns3::FqCoDelQueueDisc");
  tch.SetRootQueueDisc("ns3::FifoQueueDisc",
                     "MaxSize",
                     StringValue("100p"));
  QueueDiscContainer qdiscs = tch.Install(bottleneckDevs.Get(0));

  Ptr<QueueDisc> rootQdisc = (qdiscs.GetN() > 0) ? qdiscs.Get(0) : nullptr;
  if (!rootQdisc)
  {
    NS_FATAL_ERROR("Failed to install root queue disc on bottleneck device");
  }

  std::cout << "Using bottleneck root qdisc: "
            << rootQdisc->GetInstanceTypeId().GetName() << std::endl;

  PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), legitPort));
  ApplicationContainer sinkApps = sinkHelper.Install(victim.Get(0));
  sinkApps.Start(Seconds(0.0));
  sinkApps.Stop(Seconds(simStop));

  Ptr<PacketSink> legitSink = DynamicCast<PacketSink>(sinkApps.Get(0));

  for (uint32_t i = 0; i < legitClients.GetN(); ++i)
  {
    BulkSendHelper bulk("ns3::TcpSocketFactory",
                        InetSocketAddress(bottleneckIfs.GetAddress(1), legitPort));
    bulk.SetAttribute("SendSize", UintegerValue(legitSendSize));
    bulk.SetAttribute("MaxBytes", UintegerValue(0));

    ApplicationContainer app = bulk.Install(legitClients.Get(i));
    app.Start(Seconds(1.0 + 0.1 * i));
    app.Stop(Seconds(simStop - 0.5));
  }

  Ptr<UniformRandomVariable> jitterRv = CreateObject<UniformRandomVariable>();
  
  for (uint32_t i = 0; i < attackers.GetN(); ++i)
  {
      Address destination = bottleneckIfs.GetAddress(1);
      Address source;
      PingHelper ping(destination, source);

      ping.SetAttribute("Interval",
                        TimeValue(Seconds(1.0 / std::max(1.0, icmpPpsPerAttacker))));
      ping.SetAttribute("Size", UintegerValue(icmpPayloadSize));

      uint32_t count = static_cast<uint32_t>(
          std::ceil((attackStop - attackStart) * std::max(1.0, icmpPpsPerAttacker)));
      ping.SetAttribute("Count", UintegerValue(count));

      ApplicationContainer app = ping.Install(attackers.Get(i));
      double jitter = jitterRv->GetValue(0.0, std::max(0.0, attackStartJitterMax));
      app.Start(Seconds(attackStart + jitter));
      app.Stop(Seconds(attackStop));
  }

  MetricsState state;
  state.throughputCsv.open(outputDir + "/throughput.csv", std::ios::out);
  state.queueCsv.open(outputDir + "/queue.csv", std::ios::out);
  state.dropsCsv.open(outputDir + "/drops.csv", std::ios::out);
  state.throughputCsv << "time_s,legit_tcp_mbps,icmp_mbps,phase\n";
  state.queueCsv << "time_s,qdisc_packets,phase\n";
  state.dropsCsv << "time_s,drop_packets_interval,drop_packets_cumulative,phase\n";
  state.legitSink = legitSink;
  state.rootQdisc = rootQdisc;
  state.sampleInterval = sampleInterval;
  state.attackStart = attackStart;
  state.attackStop = attackStop;
  state.simStop = simStop;

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor;
  if (enableFlowMonitor)
  {
    monitor = flowmon.InstallAll();
  }

  if (enablePcap)
  {
    bottleneck.EnablePcap(outputDir + "/pcap/router-bottleneck", bottleneckDevs.Get(0), true);
    bottleneck.EnablePcap(outputDir + "/pcap/victim-bottleneck", bottleneckDevs.Get(1), true);
  }

  bool traceOk = bottleneckDevs.Get(1)->TraceConnectWithoutContext("MacRx",
      MakeCallback(&VictimMacRxTrace));
  std::cout << "Attached victim MacRx trace: " << (traceOk ? "yes" : "no") << std::endl;

  Simulator::Schedule(Seconds(sampleInterval), &SampleMetrics, &state);
  Simulator::Stop(Seconds(simStop));
  Simulator::Run();

  if (enableFlowMonitor && monitor)
  {
    monitor->SerializeToXmlFile(outputDir + "/flowmonitor.xml", true, true);
  }

  state.throughputCsv.close();
  state.queueCsv.close();
  state.dropsCsv.close();

  std::ofstream summary(outputDir + "/summary.csv", std::ios::out);
  summary << "metric,pre,during,post\n";
  summary << std::fixed << std::setprecision(6);
  summary << "avg_legit_tcp_mbps," << Avg(state.sumLegitPre, state.nPre) << ","
          << Avg(state.sumLegitDuring, state.nDuring) << ","
          << Avg(state.sumLegitPost, state.nPost) << "\n";
  summary << "avg_icmp_mbps," << Avg(state.sumIcmpPre, state.nPre) << ","
          << Avg(state.sumIcmpDuring, state.nDuring) << ","
          << Avg(state.sumIcmpPost, state.nPost) << "\n";
  summary << "avg_qdisc_packets," << Avg(state.sumQueuePre, state.nPre) << ","
          << Avg(state.sumQueueDuring, state.nDuring) << ","
          << Avg(state.sumQueuePost, state.nPost) << "\n";
  summary << "total_drop_packets,0," << state.lastDropPackets << ",0\n";
  summary << "max_qdisc_packets,0," << state.maxQdiscPackets << ",0\n";
  summary.close();

  Simulator::Destroy();
  return 0;
}
