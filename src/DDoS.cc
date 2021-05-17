#include "DDoS.hpp"
#include "PacketParser.hpp"
#include "Recovery.hpp"
#include <boost/lexical_cast.hpp>



namespace runos {

REGISTER_APPLICATION(DDoS, {"controller", "host-manager", 
				"switch-manager", "link-discovery", ""})

std::string InvertIP(std::string ip) {
	std::vector<std::string> fragms;
	std::string fragm = "";
	for (char c : ip) {
		if (c == '.') {
			fragms.push_back(fragm);
			fragm = "";
		} else {
			fragm += c;
		}
	}
	fragms.push_back(fragm);
	std::string res = "";
	for (int i = 3; i > 0; i--) {
		res += fragms[i] + '.';
	}
	return res + fragms[0];
}

void DDoS::DelAllFlows (std::string MAC) {
	for (auto i : IMP -> SwitchTable) {
		of13::FlowMod fm1, fm2, fm3, fm4;
		std::stringstream ss;
		fm1.command(of13::OFPFC_DELETE);
		fm2.command(of13::OFPFC_DELETE);
		fm3.command(of13::OFPFC_DELETE);
		fm4.command(of13::OFPFC_DELETE);
		fm1.table_id(of13::OFPTT_ALL);
		fm2.table_id(of13::OFPTT_ALL);
		fm3.table_id(of13::OFPTT_ALL);
		fm4.table_id(of13::OFPTT_ALL);
		fm1.priority(2);
		fm2.priority(2);
		fm3.priority(2);
		fm4.priority(2);
		fm1.cookie(0x0);
		fm2.cookie(0x0);
		fm3.cookie(0x0);
		fm4.cookie(0x0);
		fm1.cookie_mask(0);
		fm2.cookie_mask(0);
		fm3.cookie_mask(0);
		fm4.cookie_mask(0);
		fm1.idle_timeout(uint64_t(60));
		fm2.idle_timeout(uint64_t(60));
		fm3.idle_timeout(uint64_t(60));
		fm4.idle_timeout(uint64_t(60));
		fm1.hard_timeout(uint64_t(1800));
		fm2.hard_timeout(uint64_t(1800));
		fm3.hard_timeout(uint64_t(1800));
		fm4.hard_timeout(uint64_t(1800));
		ethaddr etheraddr(MAC);
		ss.str(std::string());
		ss.clear();
		ss << etheraddr;
		fm1.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
		fm2.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
		fm3.add_oxm_field(new of13::EthDst{fluid_msg::EthAddress(ss.str())});
		fm4.add_oxm_field(new of13::EthDst{fluid_msg::EthAddress(ss.str())});
		fm1.out_port(of13::OFPP_ANY);
		fm2.out_port(of13::OFPP_ANY);
		fm3.out_port(of13::OFPP_ANY);
		fm4.out_port(of13::OFPP_ANY);
		fm1.out_group(of13::OFPP_ANY);
		fm2.out_group(of13::OFPP_ANY);
		fm3.out_group(of13::OFPP_ANY);
		fm4.out_group(of13::OFPP_ANY);
		sender_->send(i.first, fm1);
		sender_->send(i.first, fm2);
		sender_->send(i.first, fm3);
		sender_->send(i.first, fm4);
	}
}

void DDoS::DelOldFlows (std::string MAC, std::string IP, uint64_t dpid, uint32_t port) {
	uint16_t priority = 2;

	of13::FlowMod fm1, fm2;
	fm1.command(of13::OFPFC_DELETE);
	fm2.command(of13::OFPFC_DELETE);
	fm1.xid(2);
	fm2.xid(2);
	fm1.buffer_id(0);
	fm2.buffer_id(0);
	fm1.priority(priority);
	fm2.priority(priority);
	fm1.cookie(0x2);
	fm2.cookie(0x2);
	fm1.idle_timeout(0);
	fm2.idle_timeout(0);
	fm1.hard_timeout(0);
	fm2.hard_timeout(0);
	fm1.flags(of13::OFPFF_SEND_FLOW_REM);
	fm2.flags(of13::OFPFF_SEND_FLOW_REM);
	fm1.add_oxm_field(new of13::EthType(0x0800));
	fm2.add_oxm_field(new of13::EthType(0x0806));
	fm1.add_oxm_field(new of13::InPort(port));
	fm2.add_oxm_field(new of13::InPort(port));
	sender_->send(dpid, fm1);
	sender_->send(dpid, fm2);

	priority = 3;

	of13::FlowMod fm3, fm4;
	std::stringstream ss;
	fm3.command(of13::OFPFC_DELETE); 
	fm4.command(of13::OFPFC_DELETE);
	fm3.xid(3); 
	fm4.xid(3);
	fm3.buffer_id(OFP_NO_BUFFER); 
	fm4.buffer_id(OFP_NO_BUFFER);
	fm3.table_id(0); 
	fm4.table_id(0);
	fm3.priority(priority); 
	fm4.priority(priority);
	fm3.cookie(0x3); 
	fm4.cookie(0x3);
	fm3.idle_timeout(uint64_t(0)); 
	fm4.idle_timeout(uint64_t(0));
	fm3.hard_timeout(uint64_t(0)); 
	fm4.hard_timeout(uint64_t(0));
	fm3.flags(of13::OFPFF_SEND_FLOW_REM); 
	fm4.flags(of13::OFPFF_SEND_FLOW_REM);
	fm3.add_oxm_field(new of13::EthType(0x0800)); 
	fm4.add_oxm_field(new of13::EthType(0x0806));
	fm3.add_oxm_field(new of13::InPort(port)); 
	fm4.add_oxm_field(new of13::InPort(port));
	ethaddr eth_src(MAC);
	ss.str(std::string());
	ss.clear();
	ss << eth_src;
	fm3.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
	fm4.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress (ss.str())});
	ipv4addr ipv4_src(convert(IP).first);
	ss.str(std::string());
	ss.clear();
	ss << ipv4_src;
	fm3.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress (ss.str())});

	of13::GoToTable go_to_table(1);
	fm3.add_instruction(go_to_table);
	fm4.add_instruction(go_to_table);
	sender_->send(dpid, fm3);
	sender_->send(dpid, fm4);
}

void DDoS::AddFlows (std::string MAC, 
		std::string IP, uint64_t dpid, uint32_t port) {
	of13::FlowMod fm1, fm2;
	fm1.command(of13::OFPFC_ADD);
	fm2.command(of13::OFPFC_ADD);
	fm1.xid(0);
	fm2.xid(0);
	fm1.buffer_id(OFP_NO_BUFFER);
	fm2.buffer_id(OFP_NO_BUFFER);
	fm1.table_id(0);
	fm2.table_id(0);
	fm1.priority(2);
	fm2.priority(2);
	fm1.cookie(0x2);
	fm2.cookie(0x2);
	fm1.idle_timeout(0);
	fm2.idle_timeout(0);
	fm1.hard_timeout(0);
	fm2.hard_timeout(0);
	fm1.flags( of13::OFPFF_SEND_FLOW_REM );
	fm2.flags( of13::OFPFF_SEND_FLOW_REM );
	fm1.add_oxm_field(new of13::EthType(0x0800));
	fm2.add_oxm_field(new of13::EthType(0x0806));
	fm1.add_oxm_field(new of13::InPort(port));
	fm2.add_oxm_field(new of13::InPort(port));
	sender_->send(dpid, fm1);
	sender_->send(dpid, fm2);

	of13::FlowMod fm3, fm4;
	std::stringstream ss;
	fm3.command(of13::OFPFC_ADD);
	fm4.command(of13::OFPFC_ADD);
	fm3.xid(3);
	fm4.xid(3);
	fm3.buffer_id(OFP_NO_BUFFER);
	fm4.buffer_id(OFP_NO_BUFFER);
	fm3.table_id(0);
	fm4.table_id(0);
	fm3.priority(3);
	fm4.priority(3);
	fm3.cookie(0x3);
	fm4.cookie(0x3);
	fm3.idle_timeout(uint64_t(0));
	fm4.idle_timeout(uint64_t(0));
	fm3.hard_timeout(uint64_t(0));
	fm4.hard_timeout(uint64_t(0));
	fm3.flags( of13::OFPFF_SEND_FLOW_REM );
	fm4.flags( of13::OFPFF_SEND_FLOW_REM );
	fm3.add_oxm_field(new of13::EthType(0x0800));
	fm4.add_oxm_field(new of13::EthType(0x0806));
	fm3.add_oxm_field(new of13::InPort(port));
	fm4.add_oxm_field(new of13::InPort(port));
	ethaddr eth_src(MAC);
	ss.str(std::string());
	ss.clear();
	ss << eth_src;
	fm3.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
	fm4.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
	ipv4addr ipv4_src(convert(IP).first);
	ss.str(std::string());
	ss.clear();
	ss << ipv4_src;
	fm3.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress (ss.str())});
	of13::GoToTable go_to_table(1);
	fm3.add_instruction(go_to_table);
	fm4.add_instruction(go_to_table);
	sender_->send(dpid, fm3);
	sender_->send(dpid, fm4);
}

bool InfoModule::SwitchInfo::hasPortsOn () {
	bool F = false;
	for (auto i : Ports) {
		if (i.second == true) {
			F = true;
			break;
		}
	}
	return F;
}



MLModule::Unit::Unit (ipv4addr SI, ipv4addr DI, uint32_t SP, uint32_t DP, PType pt, bool T) {
	SIP = (float)(uint32_t)SI / 0xFFFFFFFF;
	DIP = (float)(uint32_t)DI / 0xFFFFFFFF;
	SP = (float)(uint32_t)SP / 0xFFFFFFFF;
	DIP = (float)(uint32_t)DP / 0xFFFFFFFF;
	pt == IP ? PT = 0 : PT = 1;
	Type = T;
}

MLModule::Unit::Unit (uint32_t SI, uint32_t DI, uint32_t SP, uint32_t DP, PType pt, bool T) {
	SIP = (float)(uint32_t)SI / 0xFFFFFFFF;
	DIP = (float)(uint32_t)DI / 0xFFFFFFFF;
	SP = (float)(uint32_t)SP / 0xFFFFFFFF;
	DIP = (float)(uint32_t)DP / 0xFFFFFFFF;
	pt == IP ? PT = 0 : PT = 1;
	Type = T;
}

MLModule::Unit::Unit (float a1, float a2, float a3, float a4, float a5, bool t = true) {
	SIP = a1;
	DIP = a2;
	SP = a3;
	DP = a4;
	PT = a5;
	Type = t;
}

float MLModule::Dist(Unit &A, Unit &B) {
	return pow((A.SIP - B.SIP), 2) + pow((A.DIP - B.DIP), 2) +
		pow((A.SP - B.SP), 2) + pow((A.DP - B.SP), 2) +
		pow((A.Type - B.Type), 2);
}

int MLModule::NewCentr(std::vector<int>& Cluster) {
	Unit tmp(0, 0, 0, 0, 0);
	for (int i = 0; i < Cluster.size(); i++) {
		tmp = tmp + Dataset[Cluster[i]];
	}
	tmp = tmp / (int)Cluster.size();
	int Best = Cluster[0];
	float BestD = Dist(tmp, Dataset[Cluster[0]]);
	for (int i = 1; i < Cluster.size(); i++) {
		float tmpD = Dist(tmp, Dataset[Cluster[i]]);
		if (tmpD < BestD) {
			BestD = tmpD;
			Best = Cluster[i];
		}
	}
	return Best;
}

void MLModule::addUnit(Unit U) {
	Dataset.push_back(U);
}

void MLModule::SubClustering (std::vector<std::vector<int>> &Clasters, std::vector<int> &Centr) {
	Clasters.clear();
	LOG(INFO) << "K:" << K;
	for (int i; i < K; i++) {
		Clasters.push_back(std::vector<int>());
		Clasters[i].push_back(Centr[i]);
		LOG(INFO) << i << " center is " << Centr[i] << Dataset[Centr[i]].SIP;
	}

	LOG(INFO) << "DSS:" << Dataset.size();
	for (int i = 0; i < Dataset.size(); i++) {
		int Best = 0;
		float BestD = Dist(Dataset[i], Dataset[Centr[0]]);
		for (int j = 1; j < K; j++) {
			float tmp = Dist(Dataset[i], Dataset[Centr[j]]);
			if (tmp < BestD) {
				Best = j;
				BestD = tmp;
			}
			Clasters[j].push_back(i);
		}
	}
}

void MLModule::Clustering() {
	srand(time(NULL));
	std::vector<std::vector<int>> First, Second;
	std::vector<int> Centr;
	for (int i = 0; i < K; i++) {
		int tmp = rand() % K;
		bool flg = true;
		for (int j = 0; j < Centr.size(); j++) {
			if (tmp == Centr[j]) {
				i--;
				flg = false;
				break;
			}
		}
		if (flg) {
			Centr.push_back(tmp);
		}
	}
	SubClustering(First, Centr);
	int iter = 50;
	while (iter > 0) {
		for (int i = 0; i < K; i++) {
			Centr[i] = NewCentr(First[i]);
		}
		SubClustering(Second, Centr);
		for (auto i : First) {
			std::sort(i.begin(), i.end());
		}
		for (auto i : Second) {
			std::sort(i.begin(), i.end());
		}
		bool flg = true;
		for (int i = 0; i < K; i++) {
			if (First[i] != Second[i]) {
				flg = false;
				break;
			}
		}
		if (flg) {
			iter = 0;
		} else {
			iter--;
		}
		First.clear();
		First = Second;
		Second.clear();
	}
	Res.clear();
	for (int i = 0; i < K; i++) {
		int tmp = 0;
		for (int j : First[i]) {
			if (Dataset[j].Type) {
				tmp++;
			} else {
				tmp--;
			}
		}
		Res.push_back(std::pair<Unit, bool>(Dataset[Centr[i]], tmp >= 0 ? true : false));
	}
}

void DDoS::learn() {
	//MLMP->setK(20);
	srand(time(NULL));
	for (auto i : IMP->HostTable) {
		for (auto j : IMP->HostTable) {
			if (i.first != j.first) {
				MLModule::Unit tmp(i.second.IP, j.second.IP, i.second.Port, j.second.Port, 					IP, true);
				MLMP->addUnit(tmp);
				tmp = MLModule::Unit(i.second.IP, j.second.IP, i.second.Port, 
						j.second.Port, ARP, true);
				MLMP->addUnit(tmp);
				uint32_t InfIP = rand() % 0xFFFFFFFF, InfPort = rand() % 0xFFFFFFFF;
				tmp = MLModule::Unit((uint32_t)i.second.IP, InfIP, i.second.Port, 
						InfPort, IP, false);
				MLMP->addUnit(tmp);
				tmp = MLModule::Unit((uint32_t)i.second.IP, InfIP, i.second.Port, 
						InfPort, ARP, false);
				MLMP->addUnit(tmp);
			}
		}
	}
	MLMP->setK(20);
	if (!MLMP->Working) {
		MLMP->Working = true;
		LOG(INFO) << "WORK";
		MLMP->Clustering();
		MLMP->Working = false;
		LOG(INFO) << "FREE";
	}
}

bool MLModule::KNN(Unit &Test) {
	std::vector<std::pair<int,float>> Best;
	for (int i = 0; i < 3; i++) {
		Best.push_back(std::pair<int, float>(i, Dist(Test, Res[i].first)));
	}
	for (int i = 0; i < 3; i++) {
		float max = Best[i].second;
		int maxi = i;
		for (int j = i; j < 3; j++) {
			if (max < Best[j].second) {
				max = Best[j].second;
				maxi = j;
			}
		}
		std::pair<int, float> tmp = Best[i];
		Best[i] = Best[maxi];
		Best[maxi] = tmp;
	}
	for (int i = 3; i < Res.size(); i++) {
		if (Best[0].second > Dist(Test, Res[i].first)) {
			Best[0] = std::pair<int, float>(i, Dist(Test, Res[i].first));
			for (int i = 0; i < 3; i++) {
				float max = Best[i].second;
				int maxi = i;
				for (int j = i; j < 3; j++) {
					if (max < Best[j].second) {
						max = Best[j].second;
						maxi = j;
					}
				}
				std::pair<int, float> tmp = Best[i];
				Best[i] = Best[maxi];
				Best[maxi] = tmp;
			}
		}
	}
	int tmp = 0;
	for (auto i : Best) {
		Res[i.first].second ? tmp += 1 : tmp -= 1;
	}
	return tmp >= 0;
}

std::string InfoModule::HostInfo::getMAC() {
	return boost::lexical_cast<std::string>(MAC);
}

std::string InfoModule::HostInfo::getIP() {
	return boost::lexical_cast<std::string>(IP);
}

void DDoS::init(Loader *loader, const Config &config) {
	HostManager* host_manager_ = HostManager::get(loader);
	LinkDiscovery* link_discovery_ = dynamic_cast<LinkDiscovery*>(LinkDiscovery::get(loader));
	switch_manager_ = SwitchManager::get(loader);
	sender_ = OFMsgSender::get(loader);

	QObject::connect(host_manager_, &HostManager::hostDiscovered, this, 
			&DDoS::onHostDiscovered);

	QObject::connect(switch_manager_, &SwitchManager::switchUp, this, 
			&DDoS::onSwitchUp);
	
	QObject::connect(switch_manager_, &SwitchManager::switchDown, this, 
			&DDoS::onSwitchDown);
	
	QObject::connect(switch_manager_, &SwitchManager::linkUp, this, 
			&DDoS::onLinkUp);
	
	QObject::connect(switch_manager_, &SwitchManager::linkDown, this, 
			&DDoS::onLinkDown);
	
	QObject::connect(link_discovery_, &LinkDiscovery::linkDiscovered, this, 
			&DDoS::onLinkDiscovered);

	handler_ = Controller::get(loader)->register_handler(
	[this](of13::PacketIn& pi, OFConnectionPtr ofconn) -> bool
	{
		PacketParser pp(pi);
		runos::Packet& pkt(pp);
		LOG(INFO) << "HANDLER";
		const auto ofb_eth_type = oxm::eth_type();
		const auto ofb_ipv4_src = oxm::ipv4_src();
		const auto ofb_eth_src = oxm::eth_src();
		const auto ofb_in_port = oxm::in_port();
		const auto ofb_arp_spa = oxm::arp_spa();

		ipv4addr src_ip(convert("0.0.0.0").first);
		if (pkt.test(ofb_eth_type == 0x0800)) {
			src_ip = ipv4addr(pkt.load(ofb_ipv4_src));
		} else if (pkt.test(ofb_eth_type == 0x0806)) {
			src_ip = ipv4addr(pkt.load(ofb_arp_spa));
		}
		ethaddr src_mac = pkt.load(ofb_eth_src);
		uint32_t in_port = pkt.load(ofb_in_port);
		uint64_t dpid = ofconn->dpid();

		std::string str_mac = boost::lexical_cast<std::string>(src_mac);
		std::string str_ip = InvertIP(boost::lexical_cast<std::string>(src_ip));
		auto it = IMP->HostTable.find(str_mac);
		if (it != IMP->HostTable.end()) {
			if (CMP->Packets == 0) {
				CMP->Start = time(NULL);
			}
			CMP->Packets++;
			if (CMP->Packets == CMP->Period) {
				CMP->End = time(NULL);
				int Time = CMP->End - CMP->Start;
				//CMP->Start = time(NULL);
				float Rate = (float) CMP->Packets / Time;
				CMP->Packets = 0;
				if (Rate > CMP->RateT) {
					CMP->ATTACK = true;
					LOG(INFO) << "ATTACK";
				} else {
					CMP->ATTACK = false;
				}
			}
			if ((str_ip != "0.0.0.0") && (it->second.IP != convert("0.0.0.0").first)) {
				AddFlows(str_mac, str_ip, it->second.DPID, it->second.Port);
				it->second.Status = true;
				it->second.IP = convert(str_ip).first;
				auto itS = IMP->SwitchTable.find(it->second.DPID);
				if (itS != IMP->SwitchTable.end()) {
					auto itPort = itS->second.Ports.find(it->second.Port);
					if (itPort != itS->second.Ports.end()) {
						itPort->second = true;
					}
					//std::pair<uint64_t, uint32_t> key(it->second.DPID, it->second.Port);
					std::string key = 
						boost::lexical_cast<std::string>(it->second.DPID) +
						boost::lexical_cast<std::string>(it->second.Port);
					IMP->SP2MAC.emplace(key, str_mac);
				}
			} else {
				if ((str_ip != "0.0.0.0") && (it->second.IP != convert(str_ip).first)) {
					DelOldFlows(str_mac, it->second.getIP(),
							it->second.DPID, it->second.Port);
					DelAllFlows(str_mac);
					AddFlows(str_mac, str_ip, it->second.DPID, 
							it->second.Port);
					it->second.Status = true;
					it->second.IP = convert(str_ip).first;
				} else if ((str_ip != "0.0.0.0") && 
						(it->second.IP == convert("0.0.0.0").first) && 
						!(it->second.Status)) {
					DelOldFlows(str_mac, str_ip, 
							it->second.DPID, it->second.Port);
					DelAllFlows(str_mac);
					AddFlows(str_mac, str_ip, dpid, in_port);
					if (dpid != it->second.DPID) {
						it->second.DPID = dpid;
						it->second.Port = in_port;
						it->second.Status = true;
					} else if (in_port != it->second.Port) {
						it->second.Port = in_port;
						it->second.Status = true;
					}
					auto itS = IMP->SwitchTable.find(it->second.DPID);
					if (itS != IMP->SwitchTable.end()) {
						auto itPort = itS->second.Ports.find(it->second.Port);
						if (itPort != itS->second.Ports.end()) {
							itPort->second = true;
						}
						//std::pair<uint64_t, uint32_t> key(it->second.DPID, it->second.Port);
						std::string key = 
							boost::lexical_cast<std::string>(it->second.DPID)+
							boost::lexical_cast<std::string>(it->second.Port);

						IMP->SP2MAC.emplace(key, str_mac);
					}
				}
			}
			if (CMP->ATTACK) {
				const auto ofb_ipv4_dst = oxm::ipv4_dst();
				const auto ofb_arp_tpa = oxm::arp_tpa();
				ipv4addr dst_ip(convert("0.0.0.0").first);
				PType ProtoType;
				if (pkt.test(ofb_eth_type == 0x0800)) {
					ProtoType = IP;
					dst_ip = ipv4addr(pkt.load(ofb_ipv4_dst));
				} else if (pkt.test(ofb_eth_type == 0x0806)) {
					ProtoType = ARP;
					dst_ip = ipv4addr(pkt.load(ofb_arp_tpa));
				}
				MLModule::Unit test(src_ip, dst_ip, in_port, 0, ProtoType, true);
				MLMP->KNN(test);
			}	
		}
		return false;
	}, -1000);
}

void DDoS::onSwitchUp(SwitchPtr dev) {
	LOG(INFO) << "Switch UP";
	uint64_t dpid = dev->dpid();
	auto SwitchIter = IMP->SwitchTable.find(dpid);
	if (SwitchIter != IMP->SwitchTable.end()) {
		IMP->SwitchTable[dpid].SwitchStatus = true;
	} else {
		IMP->SwitchTable.emplace(dpid, InfoModule::SwitchInfo(true));
	}
	for (auto i : IMP->HostTable) {
		if (i.second.DPID == dpid) {
			i.second.Status = true;
		}
	}
}

void DDoS::onSwitchDown(SwitchPtr dev) {
	uint64_t dpid = dev->dpid();
	auto SwitchIter = IMP->SwitchTable.find(dpid);
	if (SwitchIter != IMP->SwitchTable.end()) {
		IMP->SwitchTable[dpid].SwitchStatus = false;
	} else {
		//unknown switch
	}
	for (auto i : IMP->HostTable) {
		if (i.second.DPID == dpid) {
			i.second.Status = false;
		}
	}
}

void DDoS::onLinkUp(PortPtr dev) {
	uint64_t dpid = dev->switch_()->dpid();
	LOG(INFO) << "1!!!!!!!!11";
	auto SwitchIter = IMP->SwitchTable.find(dpid);
	LOG(INFO) << "22222222222222";
	if (SwitchIter != IMP->SwitchTable.end()) {
		uint32_t port = dev->number();
		auto PortIter = SwitchIter->second.Ports.find(port);
		if (PortIter != SwitchIter->second.Ports.end()) {
			SwitchIter->second.SwitchStatus = true;
			PortIter->second = true;
		} else {
			IMP->SwitchTable[dpid].Ports.emplace(port, true);
		}
	}
}

void DDoS::onLinkDown(PortPtr dev) {
	uint64_t dpid = dev->switch_()->dpid();
	uint32_t port = dev->number();
	auto SwitchIter = IMP->SwitchTable.find(dpid);
	if (SwitchIter != IMP->SwitchTable.end()) {
		auto PortIter = SwitchIter->second.Ports.find(port);
		if (PortIter != SwitchIter->second.Ports.end()) {
			PortIter->second = false;
		}
		std::string mac = "";
		std::string ip = "";
		for (auto i : IMP->HostTable) {
			if (i.second.DPID == dpid && i.second.Port == port) {
				mac += i.second.getMAC();
				ip += i.second.getIP();
				break;
			}
		}
		DelOldFlows(mac, ip, dpid, port);
		DelAllFlows(mac);

		if (!SwitchIter->second.hasPortsOn() && SwitchIter->second.SwitchStatus) {
			SwitchIter->second.SwitchStatus = false;
			for (auto i : IMP->HostTable) {
				if (i.second.DPID == dpid) {
					i.second.Status = false;
				}
			}
		}
	}
	//std::pair<uint64_t, uint32_t> key(dpid, port);
	std::string key = 
		boost::lexical_cast<std::string>(dpid) +
		boost::lexical_cast<std::string>(port);
	if (IMP->SP2MAC.find(key) != IMP->SP2MAC.end()) {
		auto HostIter = IMP->HostTable.find(IMP->SP2MAC[key]);
		if (HostIter != IMP->HostTable.end()) {
			HostIter->second.Status = false;
			DelOldFlows(HostIter->second.getMAC(), 
					HostIter->second.getIP(), dpid, port);
			DelAllFlows(HostIter->second.getMAC());
		}
	}
}

void DDoS::onLinkDiscovered(switch_and_port from, switch_and_port to) {
	uint64_t sdpid = from.dpid, ddpid = to.dpid;
	uint32_t sport = from.port, dport = to.port;
	auto SwitchIter = IMP->SwitchTable.find(sdpid);
	if (SwitchIter != IMP->SwitchTable.end()) {
		SwitchIter->second.SwitchStatus = true;
		auto PortIter = SwitchIter->second.Ports.find(sport);
		if (PortIter != SwitchIter->second.Ports.end()) {
			PortIter->second = true;
		} else {
			IMP->SwitchTable[sdpid].Ports.emplace(sport, true);
		}
	} else {
		InfoModule::SwitchInfo si(true);
		si.Ports.emplace(sport, true);
		IMP->SwitchTable.emplace(sdpid, si);
	}
	SwitchIter = IMP->SwitchTable.find(ddpid);
	if (SwitchIter != IMP->SwitchTable.end()) {
		SwitchIter->second.SwitchStatus = true;
		auto PortIter = SwitchIter->second.Ports.find(dport);
		if (PortIter != SwitchIter->second.Ports.end()) {
			PortIter->second = true;
		} else {
			IMP->SwitchTable[ddpid].Ports.emplace(dport, true);
		}
	} else {
		InfoModule::SwitchInfo si(true);
		si.Ports.emplace(dport, true);
		IMP->SwitchTable.emplace(ddpid, si);
	}
}

void DDoS::onHostDiscovered(Host* dev) {
	if (dev->mac() != "00:00:00:00::00::00") {
		if (dev->ip() == "0.0.0.0") {
			InfoModule::HostInfo DB(ethaddr(dev->mac()), convert("0.0.0.0").first, dev->switchID(), dev->switchPort());
			IMP->HostTable.emplace(dev->mac(), DB);
			auto it = IMP->SwitchTable.find(dev->switchID());
			if (it != IMP->SwitchTable.end()) {
				auto itPort = it->second.Ports.find(dev->switchPort());
				if (itPort != it->second.Ports.end()) {
				}
			}
		} else {
			InfoModule::HostInfo DB(ethaddr(dev->mac()), 
					convert(InvertIP(dev->ip())).first, 
					dev->switchID(), dev->switchPort());
			IMP->HostTable.emplace(dev->mac(), DB);
			auto it = IMP->SwitchTable.find(dev->switchID());
			if (it != IMP->SwitchTable.end()) {
				//std::pair<uint64_t, uint32_t> key(dev->switchID(), dev->switchPort());
				std::string key = 
					boost::lexical_cast<std::string>(dev->switchID()) +
					boost::lexical_cast<std::string>(dev->switchPort());
				IMP->SP2MAC.emplace(key, dev->mac());
			}
			AddFlows(dev->mac(), InvertIP(dev->ip()), 
				dev->switchID(), dev->switchPort());
		}
	}
	learn();
}

DDoS::DDoS() {
	IMP = std::make_unique<InfoModule>();
	MLMP = std::make_unique<MLModule>();
	CMP = std::make_unique<ControlModule>(20, 1000);
}


} //namespace runos
