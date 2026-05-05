# detection_system.py - Fixed DDoS Detection with Random Forest + Ryu
import pandas as pd
import joblib
import math
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)

        # Load AI model
        try:
            self.model = joblib.load('ddos_model.sav')
            self.logger.info("=== AI MODEL LOADED SUCCESSFULLY ===")
        except Exception as e:
            self.model = None
            self.logger.error("=== ERROR: ddos_model.sav NOT FOUND: %s ===", e)

        self.datapaths = {}
        self.mac_to_port  = {}    # For L2 forwarding
        self.blocked_ips  = set() # Track already-blocked IPs
        self.packetin_counter = {}
        self.PACKETIN_FLOOD_LIMIT = 20
        # Luu thong tin tan cong khi phat hien
        # {victim_ip: {proto, in_port, time, pkts_blocked, bytes_blocked}}
        self.attack_log = {}

        # FIX 1: Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("=== DDoS DETECTION SYSTEM READY ===")

    # -------------------------------------------------------
    # FIX 2: Add table-miss flow entry so packets reach controller
    # Without this, switch drops unknown packets and Mininet ping fails
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow: send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("Switch %s: table-miss flow installed", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Switch registered: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Switch removed: dpid=%s", datapath.id)

    # -------------------------------------------------------
    # FIX 3: Handle PacketIn for L2 forwarding (makes ping work!)
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse packet
        from ryu.lib.packet import packet, ethernet, ether_types, ipv4 as ipv4_lib
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        # Learn MAC -> port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Determine output port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # -------------------------------------------------------
        # Phat hien IP Spoofing qua PacketIn Flood (real-time)
        # Moi src_ip moi → 1 PacketIn moi. Neu cung 1 (in_port, dst_ip)
        # co qua nhieu PacketIn → IP Spoofing DDoS → CHAN NGAY!
        # Khong can cho 5-second poll
        # -------------------------------------------------------
        PROTO_MAP_PKT = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        ip_pkt_check = pkt.get_protocol(ipv4_lib.ipv4)
        if ip_pkt_check and out_port != ofproto.OFPP_FLOOD:
            victim_ip   = ip_pkt_check.dst
            proto_name  = PROTO_MAP_PKT.get(ip_pkt_check.proto, 'IP')
            counter_key = (dpid, in_port, victim_ip)
            self.packetin_counter[counter_key] = \
                self.packetin_counter.get(counter_key, 0) + 1

            count = self.packetin_counter[counter_key]

            if count == self.PACKETIN_FLOOD_LIMIT:
                if victim_ip not in self.blocked_ips:
                    import time as _time
                    # Tim MAC cua ke tan cong qua reverse mac_to_port
                    mac_table = self.mac_to_port.get(dpid, {})
                    attacker_mac = next(
                        (mac for mac, port in mac_table.items() if port == in_port),
                        'Unknown'
                    )
                    self.logger.warning(
                        "[CANH BAO] Phat hien tan cong DDoS kieu %s Flood IP Gia mao"
                        " | Ke tan cong: MAC=%s (cong vat ly so %d)"
                        " | Nan nhan: %s",
                        proto_name, attacker_mac, in_port, victim_ip
                    )
                    self.blocked_ips.add(victim_ip)
                    self.attack_log[victim_ip] = {
                        'proto':        proto_name,
                        'in_port':      in_port,
                        'attacker_mac': attacker_mac,
                        'start_time':   _time.time(),
                        'block_duration': 60,    # hard_timeout
                        'pkts_blocked': 0,
                        'bytes_blocked': 0
                    }
                    self.block_by_port(datapath, in_port, victim_ip, proto_name)

        # Install specific flow rule to avoid future PacketIn for this flow
        if out_port != ofproto.OFPP_FLOOD:
            # Nếu là gói IPv4 → cài flow L3 (có ipv4_src/dst)
            # → flow stats sẽ trả về IP → block đúng IP kẻ tấn công
            ip_pkt = pkt.get_protocol(ipv4_lib.ipv4)
            if ip_pkt is not None:
                # Thêm ip_proto để flow stats biết giao thức (1=ICMP, 6=TCP, 17=UDP)
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=ip_pkt.proto,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
            else:
                # ARP → cài flow chỉ match ARP (eth_type=0x0806)
                # Tránh bắt nhầm ICMP/IPv4 traffic vào flow không có IP
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
                    eth_dst=dst_mac,
                    eth_src=src_mac
                )

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst,
                idle_timeout=20,
                hard_timeout=60
            )
            datapath.send_msg(mod)

        # Send the current packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)


    # -------------------------------------------------------
    # Monitor: Request flow stats every 5 seconds
    # -------------------------------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------------------------------------
    # Entropy calculation
    # -------------------------------------------------------
    def calculate_entropy(self, data_list):
        if not data_list or len(data_list) < 2:
            return 0
        counts = pd.Series(data_list).value_counts()
        probs = counts / len(data_list)
        return -sum(probs * probs.apply(math.log2))

    # -------------------------------------------------------
    # FIX 4: Flow stats handler - correct thresholds + always show status
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if self.model is None:
            self.logger.error("No model loaded, skipping detection.")
            return

        body = ev.msg.body
        if not body:
            return

        self.logger.info("--- Scanning traffic flows on Switch... ---")

        # -------------------------------------------------------
        # Bước 1: Thu thập tất cả flow IPv4 hợp lệ
        # -------------------------------------------------------
        from collections import defaultdict

        import time as _time

        flow_count = sum(
            1 for stat in body
            if stat.priority > 0 and stat.packet_count > 0
        )

        # -------------------------------------------------------
        # Thong ke luu luong tan cong da bi chan (Block rules priority=1000)
        # Switch dem so goi DROP trong rule → bao cao chinh xac
        # -------------------------------------------------------
        for stat in body:
            if stat.priority != 1000 or stat.packet_count == 0:
                continue
            victim_ip = stat.match.get('ipv4_dst', None)
            if victim_ip and victim_ip in self.attack_log:
                log      = self.attack_log[victim_ip]
                duration = stat.duration_sec + stat.duration_nsec / 1e9
                drop_rate = stat.packet_count / duration if duration > 0 else 0
                elapsed   = _time.time() - log['start_time']
                remaining = max(0, log['block_duration'] - elapsed)
                log['pkts_blocked']  = stat.packet_count
                log['bytes_blocked'] = stat.byte_count
                self.logger.warning(
                    "[THONG KE TAN CONG]"
                    " Ke tan cong: MAC=%s (cong %d) → Nan nhan: %s"
                    " | Kieu: %s Flood IP Gia mao"
                    " | Goi bi chan: %d goi | Du lieu: %.1f KB"
                    " | Toc do tan cong: %.0f pkt/s"
                    " | Thoi gian tu khi chan: %.0fs"
                    " | Con lai: %.0fs",
                    log['attacker_mac'], log['in_port'], victim_ip,
                    log['proto'],
                    stat.packet_count,
                    stat.byte_count / 1024,
                    drop_rate,
                    elapsed,
                    remaining
                )

        PROTO_MAP = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

        valid_flows = []   # Danh sách flow IPv4 hợp lệ để phân tích
        # Thống kê tổng hợp theo dst_ip: {dst_ip: {srcs, total_pkt_rate, in_ports, protocols}}
        dst_agg = defaultdict(lambda: {
            'srcs': set(), 'total_pkt_rate': 0.0,
            'total_byte_rate': 0.0, 'in_ports': set(), 'protocols': set()
        })

        for stat in body:
            if stat.packet_count == 0:
                continue
            if stat.priority == 0:
                continue

            src_ip = stat.match.get('ipv4_src', None)
            dst_ip = stat.match.get('ipv4_dst', None)

            if src_ip is None or dst_ip is None:
                continue

            in_port   = stat.match.get('in_port', 0)
            ip_proto  = stat.match.get('ip_proto', None)
            proto_name = PROTO_MAP.get(ip_proto, f'IP({ip_proto})')
            duration  = stat.duration_sec + stat.duration_nsec / 1e9

            # Tổng hợp theo dst → đếm TẤT CẢ flow IPv4 (kể cả flow mới)
            dst_agg[dst_ip]['srcs'].add(src_ip)
            dst_agg[dst_ip]['in_ports'].add(in_port)
            dst_agg[dst_ip]['protocols'].add(proto_name)
            if duration > 0:
                pkt_rate  = stat.packet_count / duration
                byte_rate = stat.byte_count   / duration
                dst_agg[dst_ip]['total_pkt_rate']  += pkt_rate
                dst_agg[dst_ip]['total_byte_rate'] += byte_rate

            # valid_flows (cho ML per-flow): chỉ lấy flow đủ lâu (> 0.5s)
            if duration < 0.5:
                continue

            pkt_rate     = stat.packet_count / duration
            byte_rate    = stat.byte_count   / duration
            avg_pkt_size = stat.byte_count   / stat.packet_count

            valid_flows.append({
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'pkt_rate': pkt_rate, 'byte_rate': byte_rate,
                'duration': duration, 'avg_pkt_size': avg_pkt_size,
                'in_port': in_port, 'proto': proto_name
            })

        # -------------------------------------------------------
        # Bước 2: Phát hiện IP Spoofing DDoS (--rand-source)
        # IP nội bộ Mininet: 10.x.x.x (10.0.0.x, 10.0.1.x, 10.0.2.x...)
        # IP giả mạo: ngoài dải 10.x.x.x (208.x, 45.x, 192.168.x...)
        # -------------------------------------------------------
        SPOOF_SRC_THRESHOLD = 5

        spoofed_victims = set()

        for victim_ip, agg in dst_agg.items():
            all_srcs   = agg['srcs']
            total_rate = agg['total_pkt_rate']
            protocols  = agg['protocols']
            proto_str  = '/'.join(sorted(protocols)) if protocols else 'IP'

            # Tách IP nội bộ (10.x.x.x) vs IP giả mạo (ngoài Internet)
            fake_srcs  = {ip for ip in all_srcs if not ip.startswith('10.')}
            legit_srcs = all_srcs - fake_srcs
            fake_count = len(fake_srcs)

            # Log tóm tắt mỗi dst có nhiều nguồn (giúp debug)
            if len(all_srcs) > 1 or fake_count > 0:
                self.logger.info(
                    "  [%s] dst=%s | legit=%d | fake=%d | total=%.1f pkt/s",
                    proto_str, victim_ip, len(legit_srcs), fake_count, total_rate
                )

            if fake_count >= SPOOF_SRC_THRESHOLD:
                spoofed_victims.add(victim_ip)

                if victim_ip not in self.blocked_ips:
                    attacker_ports = list(agg['in_ports'])
                    self.logger.warning(
                        "[CANH BAO] Phat hien tan cong DDoS kieu %s Flood IP Gia mao"
                        " | Nan nhan: %s | So nguon IP gia: %d"
                        " | Tong luu luong: %.0f pkt/s",
                        proto_str, victim_ip, fake_count, total_rate
                    )
                    self.blocked_ips.add(victim_ip)
                    self.block_by_port(
                        ev.msg.datapath,
                        attacker_ports[0],
                        victim_ip,
                        proto_str
                    )
                else:
                    self.logger.warning(
                        "[CANH BAO] Tan cong %s Flood IP Gia mao dang tiep dien"
                        " | Nan nhan: %s | %d nguon IP gia | %.0f pkt/s",
                        proto_str, victim_ip, fake_count, total_rate
                    )

        # -------------------------------------------------------
        # Bước 3: Per-flow ML detection (DDoS IP cố định)
        # Áp dụng cho cả UDP/TCP SYN/ICMP flood không có --rand-source
        # -------------------------------------------------------
        for flow in valid_flows:
            src_ip       = flow['src_ip']
            dst_ip       = flow['dst_ip']
            pkt_rate     = flow['pkt_rate']
            byte_rate    = flow['byte_rate']
            duration     = flow['duration']
            avg_pkt_size = flow['avg_pkt_size']
            proto        = flow['proto']

            # Bo qua flow thuoc victim da bi block hoac da detect boi IP Spoofing
            if dst_ip in spoofed_victims:
                continue
            if dst_ip in self.blocked_ips:  # Victim da bi chan → bo qua flow cu
                continue
            if src_ip in self.blocked_ips:
                continue

            features = pd.DataFrame(
                [[pkt_rate, byte_rate, duration, avg_pkt_size, flow_count]],
                columns=['pkt_rate', 'byte_rate', 'flow_dur', 'avg_pkt_size', 'flow_count']
            )
            prediction = self.model.predict(features)[0]

            if prediction == 1 and pkt_rate > 5000:
                if dst_ip in self.blocked_ips:
                    self.logger.info(
                        "[%s] Luu luong tu %s co pkt_rate cao nhung"
                        " dich da bi chan → bo qua (co the la phan hoi cua nan nhan)",
                        proto, src_ip
                    )
                else:
                    attack_type = {
                        'TCP': 'SYN Flood', 'UDP': 'UDP Flood', 'ICMP': 'ICMP Flood'
                    }.get(proto, f'{proto} Flood')

                    self.logger.warning(
                        "[CANH BAO] Phat hien tan cong DDoS kieu %s"
                        " | Ke tan cong: %s → Nan nhan: %s"
                        " | Luu luong: %.0f pkt/s | Kich thuoc goi: %.0f byte",
                        attack_type, src_ip, dst_ip, pkt_rate, avg_pkt_size
                    )
                    self.blocked_ips.add(src_ip)
                    self.block_attack(ev.msg.datapath, src_ip, proto)
            else:
                self.logger.info(
                    "[%s] Luu luong binh thuong: %s → %s"
                    " | %.2f pkt/s | %.2f B/s | %.2fs | AN TOAN",
                    proto, src_ip, dst_ip, pkt_rate, byte_rate, duration
                )


    # -------------------------------------------------------
    # Block attacker by src_ip (DDoS từ IP cố định)
    # Áp dụng cho: SYN Flood, UDP Flood, ICMP Flood (fixed IP)
    # -------------------------------------------------------
    def block_attack(self, datapath, src_ip, proto='ALL'):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.logger.error(
            "[CHAN] Da chan IP tan cong: %s (giao thuc: %s) | Thoi gian: 60 giay",
            src_ip, proto
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=[],
            hard_timeout=60,
            idle_timeout=30
        )
        datapath.send_msg(mod)

    # -------------------------------------------------------
    # Block IP Spoofing DDoS: drop theo in_port → victim_ip
    # Vì source IP là giả (--rand-source) nên phải chặn theo
    # cổng vật lý mà kẻ tấn công kết nối vào switch
    # -------------------------------------------------------
    def block_by_port(self, datapath, in_port, victim_ip, proto='ALL'):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ipv4_dst=victim_ip
        )
        self.logger.error(
            "[CHAN] Da chan tan cong %s IP Gia mao"
            " | Cong vat ly: %d → Nan nhan: %s | Thoi gian: 60 giay",
            proto, in_port, victim_ip
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=[],
            hard_timeout=60,
            idle_timeout=30
        )
        datapath.send_msg(mod)

    # -------------------------------------------------------
    # Cleanup: remove IP from blocked set after timeout
    # -------------------------------------------------------
    def unblock_ip(self, src_ip):
        self.blocked_ips.discard(src_ip)
        self.logger.info("IP %s removed from block list", src_ip)
