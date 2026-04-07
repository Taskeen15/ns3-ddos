#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/system-path.h"
#include "ns3/traffic-control-module.h"

#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UdpFloodDdosScenarioImproved");

namespace
{
Ptr<PacketSink> g_legitSink;
Ptr<PacketSink> g_attackSink;
std::ofstream g_throughputCsv;
std::ofstream g_queueCsv;
std::ofstream g_dropsCsv;
std::ofstream g_summaryCsv;

uint64_t g_lastLegitRx = 0;
uint64_t g_lastAttackRx = 0;
uint64_t g_totalQdiscDrops = 0;
uint64_t g_lastDropSample = 0;
uint32_t g_qdiscPacketsInQueue = 0;
uint32_t g_qdiscMaxPacketsObserved = 0;

double g_sampleInterval = 0.2;
double g_simTime = 20.0;
double g_attackStart = 6.0;
double g_attackStop = 14.0;

// Sampled throughput summaries for cleaner reporting.
double g_preAttackLegitMbpsSum = 0.0;
double g_preAttackAttackMbpsSum = 0.0;
uint32_t g_preAttackSamples = 0;

double g_duringAttackLegitMbpsSum = 0.0;
double g_duringAttackAttackMbpsSum = 0.0;
uint32_t g_duringAttackSamples = 0;

double g_postAttackLegitMbpsSum = 0.0;
double g_postAttackAttackMbpsSum = 0.0;
uint32_t g_postAttackSamples = 0;

void
EnsureDir(const std::string& path)
{
    SystemPath::MakeDirectories(path);
}

std::string
FormatRateString(uint64_t bps)
{
    std::ostringstream oss;
    if (bps % 1000000 == 0)
    {
        oss << (bps / 1000000) << "Mbps";
    }
    else if (bps % 1000 == 0)
    {
        oss << (bps / 1000) << "Kbps";
    }
    else
    {
        oss << bps << "bps";
    }
    return oss.str();
}

void
PacketsInQueueTrace(uint32_t oldValue, uint32_t newValue)
{
    (void) oldValue;
    g_qdiscPacketsInQueue = newValue;
    g_qdiscMaxPacketsObserved = std::max(g_qdiscMaxPacketsObserved, newValue);
}

void
QueueDropTrace(Ptr<const QueueDiscItem> item)
{
    (void) item;
    ++g_totalQdiscDrops;
}

void
AccumulatePhaseAverages(double now, double legitMbps, double attackMbps)
{
    if (now < g_attackStart)
    {
        g_preAttackLegitMbpsSum += legitMbps;
        g_preAttackAttackMbpsSum += attackMbps;
        ++g_preAttackSamples;
    }
    else if (now <= g_attackStop)
    {
        g_duringAttackLegitMbpsSum += legitMbps;
        g_duringAttackAttackMbpsSum += attackMbps;
        ++g_duringAttackSamples;
    }
    else
    {
        g_postAttackLegitMbpsSum += legitMbps;
        g_postAttackAttackMbpsSum += attackMbps;
        ++g_postAttackSamples;
    }
}

void
SampleMetrics()
{
    const double now = Simulator::Now().GetSeconds();

    const uint64_t legitRx = g_legitSink ? g_legitSink->GetTotalRx() : 0;
    const uint64_t attackRx = g_attackSink ? g_attackSink->GetTotalRx() : 0;

    const double legitMbps = ((legitRx - g_lastLegitRx) * 8.0) / (g_sampleInterval * 1e6);
    const double attackMbps = ((attackRx - g_lastAttackRx) * 8.0) / (g_sampleInterval * 1e6);
    const uint64_t dropDelta = g_totalQdiscDrops - g_lastDropSample;

    g_throughputCsv << std::fixed << std::setprecision(3) << now << ',' << legitMbps << ','
                    << attackMbps << ',' << legitRx << ',' << attackRx << '\n';

    g_queueCsv << std::fixed << std::setprecision(3) << now << ',' << g_qdiscPacketsInQueue
               << '\n';

    g_dropsCsv << std::fixed << std::setprecision(3) << now << ',' << dropDelta << ','
               << g_totalQdiscDrops << '\n';

    AccumulatePhaseAverages(now, legitMbps, attackMbps);

    g_lastLegitRx = legitRx;
    g_lastAttackRx = attackRx;
    g_lastDropSample = g_totalQdiscDrops;

    if (now + g_sampleInterval <= g_simTime + 1e-9)
    {
        Simulator::Schedule(Seconds(g_sampleInterval), &SampleMetrics);
    }
}

void
WriteSummary(const std::string& bottleneckRate,
             uint32_t nLegitClients,
             uint32_t nAttackers,
             uint32_t queueSizePackets,
             bool enableFlowMonitor,
             Ptr<FlowMonitor> monitor,
             FlowMonitorHelper& flowHelper,
             const std::string& outputDir)
{
    const uint64_t legitRx = g_legitSink ? g_legitSink->GetTotalRx() : 0;
    const uint64_t attackRx = g_attackSink ? g_attackSink->GetTotalRx() : 0;

    const double legitAvgMbpsFull = (legitRx * 8.0) / (g_simTime * 1e6);
    const double attackAvgMbpsFull = (attackRx * 8.0) / (g_simTime * 1e6);

    auto SafeAvg = [](double sum, uint32_t count) {
        return count == 0 ? 0.0 : (sum / static_cast<double>(count));
    };

    g_summaryCsv << "metric,value\n";
    g_summaryCsv << "sim_time_s," << g_simTime << '\n';
    g_summaryCsv << "sample_interval_s," << g_sampleInterval << '\n';
    g_summaryCsv << "legit_clients," << nLegitClients << '\n';
    g_summaryCsv << "attackers," << nAttackers << '\n';
    g_summaryCsv << "attack_start_s," << g_attackStart << '\n';
    g_summaryCsv << "attack_stop_s," << g_attackStop << '\n';
    g_summaryCsv << "bottleneck_rate," << bottleneckRate << '\n';
    g_summaryCsv << "bottleneck_qdisc_limit_packets," << queueSizePackets << '\n';
    g_summaryCsv << "legit_rx_bytes_total," << legitRx << '\n';
    g_summaryCsv << "attack_rx_bytes_total," << attackRx << '\n';
    g_summaryCsv << "legit_avg_mbps_full_run," << legitAvgMbpsFull << '\n';
    g_summaryCsv << "attack_avg_mbps_full_run," << attackAvgMbpsFull << '\n';
    g_summaryCsv << "pre_attack_legit_avg_mbps," << SafeAvg(g_preAttackLegitMbpsSum, g_preAttackSamples)
                 << '\n';
    g_summaryCsv << "pre_attack_attack_avg_mbps," << SafeAvg(g_preAttackAttackMbpsSum, g_preAttackSamples)
                 << '\n';
    g_summaryCsv << "during_attack_legit_avg_mbps,"
                 << SafeAvg(g_duringAttackLegitMbpsSum, g_duringAttackSamples) << '\n';
    g_summaryCsv << "during_attack_attack_avg_mbps,"
                 << SafeAvg(g_duringAttackAttackMbpsSum, g_duringAttackSamples) << '\n';
    g_summaryCsv << "post_attack_legit_avg_mbps," << SafeAvg(g_postAttackLegitMbpsSum, g_postAttackSamples)
                 << '\n';
    g_summaryCsv << "post_attack_attack_avg_mbps," << SafeAvg(g_postAttackAttackMbpsSum, g_postAttackSamples)
                 << '\n';
    g_summaryCsv << "bottleneck_qdisc_max_packets_observed," << g_qdiscMaxPacketsObserved << '\n';
    g_summaryCsv << "bottleneck_qdisc_total_drops," << g_totalQdiscDrops << '\n';

    if (enableFlowMonitor && monitor)
    {
        monitor->CheckForLostPackets();
        const auto stats = monitor->GetFlowStats();
        Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());

        uint64_t totalTxPackets = 0;
        uint64_t totalRxPackets = 0;
        uint64_t totalLostPackets = 0;
        uint64_t legitFlowRxBytes = 0;
        uint64_t attackFlowRxBytes = 0;

        for (const auto& kv : stats)
        {
            totalTxPackets += kv.second.txPackets;
            totalRxPackets += kv.second.rxPackets;
            totalLostPackets += kv.second.lostPackets;

            if (classifier)
            {
                Ipv4FlowClassifier::FiveTuple tuple = classifier->FindFlow(kv.first);
                if (tuple.destinationPort == 8080)
                {
                    legitFlowRxBytes += kv.second.rxBytes;
                }
                else if (tuple.destinationPort == 9000)
                {
                    attackFlowRxBytes += kv.second.rxBytes;
                }
            }
        }

        g_summaryCsv << "flowmonitor_total_flows," << stats.size() << '\n';
        g_summaryCsv << "flowmonitor_total_tx_packets," << totalTxPackets << '\n';
        g_summaryCsv << "flowmonitor_total_rx_packets," << totalRxPackets << '\n';
        g_summaryCsv << "flowmonitor_total_lost_packets," << totalLostPackets << '\n';
        g_summaryCsv << "flowmonitor_legit_rx_bytes," << legitFlowRxBytes << '\n';
        g_summaryCsv << "flowmonitor_attack_rx_bytes," << attackFlowRxBytes << '\n';

        monitor->SerializeToXmlFile(outputDir + "/flowmonitor.xml", true, true);
    }
}
} // namespace

int
main(int argc, char* argv[])
{
    Time::SetResolution(Time::NS);

    uint32_t nLegitClients = 3;
    uint32_t nAttackers = 16;

    std::string accessRate = "100Mbps";
    std::string accessDelay = "1ms";
    std::string bottleneckRate = "10Mbps";
    std::string bottleneckDelay = "10ms";

    std::string legitTcpRate = "3Mbps"; // used only as a pacing cap per legit sender
    uint32_t legitSendSize = 1000;

    std::string attackRatePerAttacker = "1Mbps";
    uint32_t attackPacketSize = 1000;
    double attackRateJitterFraction = 0.20; // +/-20%
    double attackStartJitterMax = 0.30;     // seconds

    double legitStart = 1.0;
    g_attackStart = 6.0;
    g_attackStop = 14.0;
    g_simTime = 20.0;
    g_sampleInterval = 0.2;

    uint16_t legitPort = 8080;
    uint16_t attackPort = 9000;

    uint32_t queueSizePackets = 100;
    std::string outputDir = "results/udp-flood-improved";
    bool enablePcap = true;
    bool enableFlowMonitor = true;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nLegitClients", "Number of legitimate TCP clients", nLegitClients);
    cmd.AddValue("nAttackers", "Number of UDP attacker nodes", nAttackers);
    cmd.AddValue("accessRate", "Rate of each access link", accessRate);
    cmd.AddValue("accessDelay", "Delay of each access link", accessDelay);
    cmd.AddValue("bottleneckRate", "Rate of router-to-victim bottleneck", bottleneckRate);
    cmd.AddValue("bottleneckDelay", "Delay of router-to-victim bottleneck", bottleneckDelay);
    cmd.AddValue("legitTcpRate", "Per-client TCP sending cap for BulkSend sockets", legitTcpRate);
    cmd.AddValue("legitSendSize", "TCP send size for legitimate traffic (bytes)", legitSendSize);
    cmd.AddValue("attackRatePerAttacker", "Base UDP flood rate per attacker", attackRatePerAttacker);
    cmd.AddValue("attackPacketSize", "Attack packet size (bytes)", attackPacketSize);
    cmd.AddValue("attackRateJitterFraction", "Relative jitter for per-attacker UDP rate", attackRateJitterFraction);
    cmd.AddValue("attackStartJitterMax", "Maximum attacker start jitter in seconds", attackStartJitterMax);
    cmd.AddValue("legitStart", "Start time for legitimate traffic", legitStart);
    cmd.AddValue("attackStart", "Attack start time", g_attackStart);
    cmd.AddValue("attackStop", "Attack stop time", g_attackStop);
    cmd.AddValue("simTime", "Total simulation time", g_simTime);
    cmd.AddValue("sampleInterval", "Sampling interval for CSV time series", g_sampleInterval);
    cmd.AddValue("queueSizePackets", "Bottleneck queue size in packets", queueSizePackets);
    cmd.AddValue("outputDir", "Directory for CSV/PCAP/XML outputs", outputDir);
    cmd.AddValue("enablePcap", "Enable bottleneck PCAP capture", enablePcap);
    cmd.AddValue("enableFlowMonitor", "Enable FlowMonitor XML + summary stats", enableFlowMonitor);
    cmd.Parse(argc, argv);

    EnsureDir(outputDir);

    NodeContainer legitClients;
    legitClients.Create(nLegitClients);

    NodeContainer attackers;
    attackers.Create(nAttackers);

    NodeContainer router;
    router.Create(1);

    NodeContainer victim;
    victim.Create(1);

    InternetStackHelper internet;
    internet.Install(legitClients);
    internet.Install(attackers);
    internet.Install(router);
    internet.Install(victim);

    PointToPointHelper access;
    access.SetDeviceAttribute("DataRate", StringValue(accessRate));
    access.SetChannelAttribute("Delay", StringValue(accessDelay));

    PointToPointHelper bottleneck;
    bottleneck.SetDeviceAttribute("DataRate", StringValue(bottleneckRate));
    bottleneck.SetChannelAttribute("Delay", StringValue(bottleneckDelay));

    std::vector<NetDeviceContainer> legitDevices;
    std::vector<Ipv4InterfaceContainer> legitIfaces;
    legitDevices.reserve(nLegitClients);
    legitIfaces.reserve(nLegitClients);

    std::vector<NetDeviceContainer> attackerDevices;
    std::vector<Ipv4InterfaceContainer> attackerIfaces;
    attackerDevices.reserve(nAttackers);
    attackerIfaces.reserve(nAttackers);

    Ipv4AddressHelper address;

    for (uint32_t i = 0; i < nLegitClients; ++i)
    {
        NetDeviceContainer devs = access.Install(legitClients.Get(i), router.Get(0));
        legitDevices.push_back(devs);

        std::ostringstream subnet;
        subnet << "10.1." << (i + 1) << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");
        legitIfaces.push_back(address.Assign(devs));
    }

    for (uint32_t i = 0; i < nAttackers; ++i)
    {
        NetDeviceContainer devs = access.Install(attackers.Get(i), router.Get(0));
        attackerDevices.push_back(devs);

        std::ostringstream subnet;
        subnet << "10.2." << (i + 1) << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");
        attackerIfaces.push_back(address.Assign(devs));
    }

    NetDeviceContainer bottleneckDevices = bottleneck.Install(router.Get(0), victim.Get(0));
    address.SetBase("10.3.0.0", "255.255.255.0");
    Ipv4InterfaceContainer bottleneckIfaces = address.Assign(bottleneckDevices);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Explicitly install and trace the exact bottleneck root queue disc.
   
    // Get or install exactly one root queue disc on the router-side bottleneck device.
    Ptr<QueueDisc> bottleneckQdisc;
    Ptr<TrafficControlLayer> tc = router.Get(0)->GetObject<TrafficControlLayer>();

    if (!tc)
    {
        NS_FATAL_ERROR("TrafficControlLayer not found on router node");
    }

    bottleneckQdisc = tc->GetRootQueueDiscOnDevice(bottleneckDevices.Get(0));

    if (!bottleneckQdisc)
    {
        TrafficControlHelper tch;
        tch.SetRootQueueDisc("ns3::FifoQueueDisc",
                            "MaxSize",
                            StringValue(std::to_string(queueSizePackets) + "p"));

        NetDeviceContainer routerSideBottleneck;
        routerSideBottleneck.Add(bottleneckDevices.Get(0));

        QueueDiscContainer qdiscs = tch.Install(routerSideBottleneck);
        bottleneckQdisc = qdiscs.Get(0);
    }

    if (!bottleneckQdisc)
    {
        NS_FATAL_ERROR("Failed to get or install bottleneck root queue disc");
    }

    bottleneckQdisc->TraceConnectWithoutContext("PacketsInQueue",
                                                MakeCallback(&PacketsInQueueTrace));
    bottleneckQdisc->TraceConnectWithoutContext("Drop",
                                                MakeCallback(&QueueDropTrace));



    bottleneckQdisc->TraceConnectWithoutContext("PacketsInQueue", MakeCallback(&PacketsInQueueTrace));
    bottleneckQdisc->TraceConnectWithoutContext("Drop", MakeCallback(&QueueDropTrace));

        std::cout << "Using bottleneck root qdisc: " << bottleneckQdisc->GetInstanceTypeId().GetName() << std::endl;

    PacketSinkHelper legitSinkHelper("ns3::TcpSocketFactory",
                                     InetSocketAddress(Ipv4Address::GetAny(), legitPort));
    ApplicationContainer legitSinkApps = legitSinkHelper.Install(victim.Get(0));
    legitSinkApps.Start(Seconds(0.0));
    legitSinkApps.Stop(Seconds(g_simTime));
    g_legitSink = DynamicCast<PacketSink>(legitSinkApps.Get(0));

    PacketSinkHelper attackSinkHelper("ns3::UdpSocketFactory",
                                      InetSocketAddress(Ipv4Address::GetAny(), attackPort));
    ApplicationContainer attackSinkApps = attackSinkHelper.Install(victim.Get(0));
    attackSinkApps.Start(Seconds(0.0));
    attackSinkApps.Stop(Seconds(g_simTime));
    g_attackSink = DynamicCast<PacketSink>(attackSinkApps.Get(0));

    Ipv4Address victimAddress = bottleneckIfaces.GetAddress(1);

    // Legitimate traffic: BulkSend is smoother and more defensible than TCP OnOff.
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(1 << 20));
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(1 << 20));

    for (uint32_t i = 0; i < nLegitClients; ++i)
    {
        BulkSendHelper bulk("ns3::TcpSocketFactory", InetSocketAddress(victimAddress, legitPort));
        bulk.SetAttribute("MaxBytes", UintegerValue(0));
        bulk.SetAttribute("SendSize", UintegerValue(legitSendSize));

        ApplicationContainer apps = bulk.Install(legitClients.Get(i));
        apps.Start(Seconds(legitStart + 0.1 * i));
        apps.Stop(Seconds(g_simTime - 0.5));
    }

    // Optional pacing cap for TCP source apps by limiting access link contention at sender side.
    // Legit traffic remains realistic because TCP adapts to congestion rather than transmitting a fixed OnOff pattern.

    Ptr<UniformRandomVariable> jitterRv = CreateObject<UniformRandomVariable>();
    const uint64_t attackBaseBps = DataRate(attackRatePerAttacker).GetBitRate();

    for (uint32_t i = 0; i < nAttackers; ++i)
    {
        const double factor = 1.0 + jitterRv->GetValue(-attackRateJitterFraction, attackRateJitterFraction);
        const uint64_t attackerBps = static_cast<uint64_t>(std::max(1.0, factor * static_cast<double>(attackBaseBps)));
        const std::string attackerRate = FormatRateString(attackerBps);
        const double startJitter = jitterRv->GetValue(0.0, attackStartJitterMax);

        OnOffHelper attackOnOff("ns3::UdpSocketFactory", InetSocketAddress(victimAddress, attackPort));
        attackOnOff.SetAttribute("DataRate", StringValue(attackerRate));
        attackOnOff.SetAttribute("PacketSize", UintegerValue(attackPacketSize));
        attackOnOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        attackOnOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer apps = attackOnOff.Install(attackers.Get(i));
        apps.Start(Seconds(g_attackStart + startJitter));
        apps.Stop(Seconds(g_attackStop));
    }

    if (enablePcap)
    {
        bottleneck.EnablePcap(outputDir + "/victim-bottleneck-router", bottleneckDevices.Get(0), true);
        bottleneck.EnablePcap(outputDir + "/victim-bottleneck-victim", bottleneckDevices.Get(1), true);
    }

    g_throughputCsv.open(outputDir + "/throughput.csv", std::ios::out);
    g_queueCsv.open(outputDir + "/queue.csv", std::ios::out);
    g_dropsCsv.open(outputDir + "/drops.csv", std::ios::out);
    g_summaryCsv.open(outputDir + "/summary.csv", std::ios::out);

    g_throughputCsv << "time_s,legit_rx_mbps,attack_rx_mbps,legit_rx_bytes_total,attack_rx_bytes_total\n";
    g_queueCsv << "time_s,bottleneck_qdisc_packets\n";
    g_dropsCsv << "time_s,bottleneck_qdisc_drops_in_interval,bottleneck_qdisc_cumulative_drops\n";

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor;
    if (enableFlowMonitor)
    {
        monitor = flowHelper.InstallAll();
    }

    Simulator::Schedule(Seconds(g_sampleInterval), &SampleMetrics);
    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();

    WriteSummary(bottleneckRate,
                 nLegitClients,
                 nAttackers,
                 queueSizePackets,
                 enableFlowMonitor,
                 monitor,
                 flowHelper,
                 outputDir);

    g_throughputCsv.close();
    g_queueCsv.close();
    g_dropsCsv.close();
    g_summaryCsv.close();

    Simulator::Destroy();
    return 0;
}
