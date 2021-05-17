#pragma once

#include "Application.hpp"
#include "Controller.hpp"
#include "api/Switch.hpp"
#include "Loader.hpp"
#include "HostManager.hpp"
#include "LinkDiscovery.hpp"
#include "SwitchManager.hpp"
#include "OFMsgSender.hpp"

#include "oxm/openflow_basic.hh"
#include "oxm/field_set.hh"

#include <string>
#include <math.h>
#include <vector>
#include <random>
#include <sys/time.h>
#include <algorithm>
#include <unordered_map>
#include <utility>

namespace runos {

namespace of13 = fluid_msg::of13;

enum PType {IP, ARP};

class MLModule {
public:
	struct Unit {
		float SIP;
		float DIP;
		float SP;
		float DP;
		float PT;
		bool Type;

		Unit (ipv4addr SI, ipv4addr DI, uint32_t SP, uint32_t DP, PType pt, bool T);
		Unit (uint32_t SI, uint32_t DI, uint32_t SP, uint32_t DP, PType pt, bool T);
		Unit (float a1, float a2, float a3, float a4, float a5, bool t);

		inline Unit operator+ (Unit& a) {
			return Unit(SIP + a.SIP, DIP + a.DIP, SP + a.SP, DP + a.DP, PT + a.PT, Type);
		}
		inline Unit operator/ (int a) {
			return Unit(SIP/a, DIP/a, SP/a, DP/a, PT/a, Type);
		}
	};

	void addUnit (Unit A);
	float Dist(Unit &A, Unit &B);
	std::vector<Unit> Dataset;
	std::vector<std::pair<Unit, bool>> Claster;
	std::vector<std::pair<Unit, bool>> Res;
	int K;
	bool Working = false;

	void SubClustering (std::vector<std::vector<int>>& Clusters, std::vector<int>& Centr);
	void Clustering ();
	int NewCentr (std::vector<int>& Cluster);
	inline void setK (int k) {
		if (k > Dataset.size()) {
			K = Dataset.size();
		} else {
			K = k;
		}
		LOG(INFO) << "K = " << K << " DSS = " << Dataset.size();
	}

	bool KNN (Unit& test);

	MLModule () {}
};

class InfoModule {
	public:
		struct SwitchInfo {
			std::unordered_map<uint32_t, bool> Ports;
			bool SwitchStatus;
			bool Edge;
			SwitchInfo (bool SS = false, bool E = false) : SwitchStatus(SS), Edge(E) {};
			bool hasPortsOn ();
			
		};

		struct HostInfo {
			ethaddr MAC;
			ipv4addr IP;
			uint64_t DPID;
			uint32_t Port;
			bool Status;
			HostInfo (ethaddr mac, ipv4addr ip, uint64_t dpid, uint32_t port, 
					bool status=false) : MAC(mac), IP(ip), DPID(dpid), 
					Port(port), Status(status) {}
			std::string getMAC();
			std::string getIP();
		
		};
		std::unordered_map<std::string, HostInfo> HostTable;
		std::unordered_map<uint64_t, SwitchInfo> SwitchTable;
		std::unordered_map<std::string, std::string> SP2MAC;
		InfoModule () {}
};


class ControlModule {
public:
	int Start;
	int End;
	int Period;
	int Packets;
	float RateT;
	bool ATTACK;
	ControlModule (int Per, int Rate) : Start(0), End(0), Period(Per), Packets(0), RateT(Rate),
				ATTACK(false) {}
	ControlModule() : Period(20), RateT(10), ATTACK(false) {} 

};

class DDoS : public Application {
	Q_OBJECT
	SIMPLE_APPLICATION(DDoS, "DDoS")

public:
	DDoS();
	void init(Loader* loader, const Config& config) override;

protected slots:
	void onHostDiscovered(Host* dev);
	void onSwitchUp(SwitchPtr dev);
	void onSwitchDown(SwitchPtr dev);
	void onLinkUp(PortPtr dev);
	void onLinkDown(PortPtr dev);
	void onLinkDiscovered(switch_and_port from, switch_and_port to);

private:
	SwitchManager* switch_manager_;
	OFMsgSender* sender_;
	OFMessageHandlerPtr handler_;
	std::unique_ptr<MLModule> MLMP;
	std::unique_ptr<InfoModule> IMP;
	std::unique_ptr<ControlModule> CMP;
	void learn();
	bool detect(MLModule::Unit & Test);

	void DelOldFlows (std::string MAC, std::string IP, uint64_t dpid, uint32_t port);
	void DelAllFlows (std::string MAC);
	void AddFlows (std::string MAC, std::string IP, uint64_t dpid, uint32_t port);
};
}//runos namespace
