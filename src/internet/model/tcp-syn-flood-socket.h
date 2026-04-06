#pragma once
#include "ns3/socket.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/address.h"
#include "ns3/random-variable-stream.h"

namespace ns3 {

class TcpL4Protocol;

class TcpSynFloodSocket : public Socket
{
public:
  static TypeId GetTypeId();
  TcpSynFloodSocket();
  ~TcpSynFloodSocket() override;

  // Socket API (truly need a subset)
  int Bind() override;
  int Bind(const Address &address) override;
  int Connect(const Address &address) override;
  int Close() override;

  int Send(Ptr<Packet> p, uint32_t flags) override;
  int SendTo(Ptr<Packet> p, uint32_t flags, const Address &toAddress) override;

  // required pure virtuals (return safe defaults)
  uint32_t GetTxAvailable() const override;
 // int GetErrno() const override;
 SocketErrno GetErrno() const override;

  Ptr<Node> GetNode() const override;

  // called by factory
  void SetTcp(Ptr<TcpL4Protocol> tcp);
  void SetNode(Ptr<Node> node);


  SocketType GetSocketType() const override;
  int Bind6() override;
  int ShutdownSend() override;
  int ShutdownRecv() override;
  int Listen() override;

  uint32_t GetRxAvailable() const override;
  Ptr<Packet> Recv(uint32_t maxSize, uint32_t flags) override;
  Ptr<Packet> RecvFrom(uint32_t maxSize, uint32_t flags, Address& fromAddress) override;

  int GetSockName(Address& address) const override;
  int GetPeerName(Address& address) const override;

  bool SetAllowBroadcast(bool allowBroadcast) override;
  bool GetAllowBroadcast() const override;
  void SetSpoofedSource(Ipv4Address src); // set 0.0.0.0 to disable


private:
  void SetupEndpoint(); // will copy/adapt from tcp-socket-base
  Address m_peer;       // saved by Connect
  Address m_local;      // optional bind address

  Ptr<TcpL4Protocol> m_tcp;
  Ptr<Node> m_node;

  // Attributes (start minimal)
  Ptr<RandomVariableStream> m_srcPortRv;
  uint16_t m_fixedSrcPort{0}; // if user binds to a port
  bool m_useFixedSrcPort{false};

  //int m_errno{0};
  SocketErrno m_errno{SocketErrno::ERROR_NOTERROR};

  Ipv4Address m_spoofedSrc{Ipv4Address("0.0.0.0")};


};

} // namespace ns3
