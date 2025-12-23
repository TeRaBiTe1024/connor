# simple_switch_final.py
# Controlador SDN para o Trabalho Final de Redes
# Suporta Experimentos 1 a 6 (Baseline, Rotas, ECMP, Falha, Segurança)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
import random

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # --- CONFIGURAÇÃO DO EXPERIMENTO ---
        # Escolha qual experimento rodar alterando o número abaixo:
        # 1: Baseline (Learning Switch padrão)
        # 2: Rota Superior Forçada (s1 -> s2 -> s4)
        # 3: Rota Inferior Forçada (s1 -> s3 -> s4)
        # 4: ECMP-sim (Balanceamento aleatório no s1)
        # 5: Tolerância a Falha (Reroteamento s1->s2 cai, usa s1->s3)
        # 6: Política de Segurança (Bloquear Handshake/DoS)
        
        self.EXPERIMENTO_ATUAL = 1 
        
        # Mapeamento de Portas (Baseado na ordem de criação do topo_malha.py)
        # S1: 1->s2, 2->s3, 3->h1
        # S2: 1->s1, 2->s4
        # S3: 1->s4, 2->s1
        # S4: 1->s2, 2->s3, 3->h2
        self.topo_ports = {
            1: {'s2': 1, 's3': 2, 'h1': 3},
            2: {'s1': 1, 's4': 2},
            3: {'s4': 1, 's1': 2},
            4: {'s2': 1, 's3': 2, 'h2': 3}
        }

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        kwargs = dict(datapath=datapath, priority=priority, match=match, instructions=inst)
        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id
            
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Regra Table-miss (envia para controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def get_out_port_sdn(self, dpid, pkt_udp, ev):
        """Lógica central dos experimentos SDN para tráfego UDP/4433"""
        
        # EXPERIMENTO 1: Baseline (Deixa o Learning Switch tratar)
        if self.EXPERIMENTO_ATUAL == 1:
            return None 

        # EXPERIMENTO 2: Rota Superior (s1->s2->s4)
        if self.EXPERIMENTO_ATUAL == 2:
            if dpid == 1: return self.topo_ports[1]['s2']
            if dpid == 2: return self.topo_ports[2]['s4']
            if dpid == 4: return self.topo_ports[4]['h2']
            
        # EXPERIMENTO 3: Rota Inferior (s1->s3->s4)
        if self.EXPERIMENTO_ATUAL == 3:
            if dpid == 1: return self.topo_ports[1]['s3']
            if dpid == 3: return self.topo_ports[3]['s4']
            if dpid == 4: return self.topo_ports[4]['h2']

        # EXPERIMENTO 4: ECMP-sim (Balanceamento em s1)
        if self.EXPERIMENTO_ATUAL == 4:
            if dpid == 1:
                # Escolha aleatória causa Jitter
                return random.choice([self.topo_ports[1]['s2'], self.topo_ports[1]['s3']])
            if dpid == 2: return self.topo_ports[2]['s4']
            if dpid == 3: return self.topo_ports[3]['s4']
            if dpid == 4: return self.topo_ports[4]['h2']

        # EXPERIMENTO 5: Falha de Link (Simulação)
        if self.EXPERIMENTO_ATUAL == 5:
            # Assumimos que o caminho preferencial é o Superior (via s2)
            # Mas se a porta 1 do s1 cair, vamos para s3.
            if dpid == 1:
                port_s2 = self.topo_ports[1]['s2']
                # Verifica estado da porta
                port_info = ev.msg.datapath.ports.get(port_s2)
                
                # Se a porta existir e estiver UP (live)
                if port_info and (port_info.state == 0 or port_info.state == 4): # 4=Live
                    return self.topo_ports[1]['s2']
                else:
                    print(f"[SDN-FAIL] Porta {port_s2} no s1 falhou! Reroteando via s3.")
                    return self.topo_ports[1]['s3']
            
            # Resto do caminho segue lógica simples
            if dpid == 2: return self.topo_ports[2]['s4']
            if dpid == 3: return self.topo_ports[3]['s4']
            if dpid == 4: return self.topo_ports[4]['h2']

        # EXPERIMENTO 6: Segurança (Bloqueio ou QoS)
        if self.EXPERIMENTO_ATUAL == 6:
            # Exemplo: Bloquear pacotes pequenos (Handshake) ou específico
            # Aqui vamos simular um DROP retornando uma ação vazia
            if dpid == 1:
                # Se o pacote for pequeno (handshake costuma ser menor), DROP
                # Ou drop aleatório para simular ataque DoS
                if random.random() < 0.5:
                    print("[SDN-SEC] Pacote suspeito bloqueado!")
                    return "DROP"
                return self.topo_ports[1]['s2']
            if dpid == 2: return self.topo_ports[2]['s4']
            if dpid == 4: return self.topo_ports[4]['h2']

        return None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)

        # Filtra LLDP/IPv6
        if eth.ethertype == 0x88cc or eth.ethertype == 0x86dd:
            return

        # --- INTERCEPTAÇÃO SDN PARA QUIC-SIM (UDP 4433) ---
        sdn_out_port = None
        if pkt_udp and (pkt_udp.dst_port == 4433 or pkt_udp.src_port == 4433):
            # Chama a lógica do experimento
            sdn_out_port = self.get_out_port_sdn(dpid, pkt_udp, ev)

            if sdn_out_port == "DROP":
                # Instala fluxo de DROP
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=4433)
                self.add_flow(datapath, 100, match, []) # Actions vazio = Drop
                return # Não processa mais nada

            if sdn_out_port is not None:
                # Se a lógica SDN definiu uma porta, instale o fluxo com prioridade alta
                print(f"[SDN-EXP-{self.EXPERIMENTO_ATUAL}] s{dpid}: QUIC via porta {sdn_out_port}")
                actions = [parser.OFPActionOutput(sdn_out_port)]
                
                # Match específico para este fluxo UDP
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=4433)
                
                # Prioridade 10 (maior que o learning switch que será 1)
                # Hard_timeout define quanto tempo a regra dura (útil p/ ECMP variar)
                timeout = 0
                if self.EXPERIMENTO_ATUAL == 4: timeout = 1 # ECMP muda rápido
                
                self.add_flow(datapath, 10, match, actions)
                
                # Envia o pacote atual
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
                return

        # --- LEARNING SWITCH (BASELINE / FALLBACK) ---
        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
