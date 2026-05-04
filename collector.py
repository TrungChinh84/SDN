from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub
import pandas as pd
import numpy as np
import os
class Collector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Collector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.file_name = "dataset.csv"
        if not os.path.isfile(self.file_name):
            headers = ["pkt_rate", "byte_rate", "flow_dur", "src_ip_ent", "dst_ip_ent", "label"]
            df = pd.DataFrame(columns=headers)
            df.to_csv(self.file_name, index=False)
            self.logger.info("--- Đã tạo mới file dataset.csv ---")
        else:
            self.logger.info("--- File đã có sẵn, dữ liệu sẽ được ghi nối tiếp ---")

    # --- PHẦN ĐỊNH TUYẾN (Giúp sửa lỗi No route to host) ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # --- PHẦN THU THẬP DỮ LIỆU ---
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER: self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER: self.datapaths.pop(datapath.id, None)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values(): self._request_stats(dp)
            hub.sleep(3)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        label = 0 # Đổi thành 1 khi tấn công
        for stat in ev.msg.body:
            if stat.priority == 1: # Chỉ lấy dữ liệu từ các luồng traffic thực tế
                dur = stat.duration_sec + stat.duration_nsec/1e9
                if dur == 0: continue
                features = [stat.packet_count/dur, stat.byte_count/dur, dur, 0, 0, label]
                pd.DataFrame([features]).to_csv(self.file_name, mode='a', header=False, index=False)
                self.logger.info(f"-> Ghi dữ liệu nhãn {label}")
