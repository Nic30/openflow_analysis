from enum import Enum


class OF_REG():
    REG_CNT = 16
    XREG_CNT = 8

    def __init__(self, name, index=None):
        self.is_reg = name.startswith("reg")
        self.is_xreg = name.startswith("xreg")
        self.is_oxm_of_metadata = name.startswith("OXM_OF_METADATA")
        self.is_tun_metadata = name.startswith("tun_metadata")
        assert (self.is_reg
                or self.is_xreg
                or self.is_oxm_of_metadata
                or self.is_tun_metadata), name
        self.name = name
        self.index = index

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.name == other.name
                and self.index == other.index)

    def __hash__(self):
        return hash((self.name, self.index))

    def __repr__(self):
        if self.index is None:
            return self.name
        else:
            return "%s[%r]" % (self.name, self.index)


class OF_RECORD_ITEM(Enum):
    # class OF_RECORD_PROTOCOL(Enum):
    ip = "ip"
    ipv6 = "ipv6"
    icmp = "icmp"
    icmp6 = "icmp6"
    tcp = "tcp"
    tcp6 = "tcp6"
    udp = "udp"
    udp6 = "udp6"
    sctp = "sctp"
    sctp6 = "sctp6"
    arp = "arp"
    rarp = "rarp"
    mpls = "mpls"
    mplsm = "mplsm"

    duration = "duration"
    in_port = "in_port"
    dl_vlan = "dl_vlan"
    dl_vlan_pcp = "dl_vlan_pcp"
    dl_type = "dl_type"
    nw_proto = "nw_proto"
    nw_frag = "nw_frag"
    ip_proto = "ip_proto"
    nw_tos = "nw_tos"
    ip_dscp = "ip_dscp"
    nw_ecn = "nw_ecn"
    ip_ecn = "ip_ecn"
    nw_ttl = "nw_ttl"
    icmp_type = "icmp_type"
    icmp_code = "icmp_code"
    table = "table"
    ipv6_label = "ipv6_label"
    mpls_bos = "mpls_bos"
    mpls_tc = "mpls_tc"
    ct_zone = "ct_zone"
    n_packets = "n_packets"
    n_bytes = "n_bytes"
    idle_age = "idle_age"
    hard_age = "hard_age"
    priority = "priority"
    arp_op = "arp_op"
    idle_timeout = "idle_timeout"
    hard_timeout = "hard_timeout"
    importance = "importance"
    cookie = "cookie"
    vlan_tci = "vlan_tci"
    tcp_src = "tcp_src"
    tcp_dst = "tcp_dst"
    udp_src = "udp_src"
    udp_dst = "udp_dst"
    sctp_src = "sctp_src"
    sctp_dst = "sctp_dst"
    tp_dst = "tp_dst"
    tp_src = "tp_src"
    mpls_label = "mpls_label"
    tun_id = "tun_id"
    tunnel_id = "tunnel_id"
    tun_gbp_id = "tun_gbp_id"
    tun_gbp_flags = "tun_gbp_flags"
    pkt_mark = "pkt_mark"
    actset_output = "actset_output"
    conj_id = "conj_id"
    ct_mark = "ct_mark"
    ct_label = "ct_label"
    metadata = "metadata"
    ct_state = "ct_state"
    nw_src = "nw_src"
    nw_dst = "nw_dst"
    arp_spa = "arp_spa"
    arp_tpa = "arp_tpa"
    tun_src = "tun_src"
    tun_dst = "tun_dst"
    ipv6_src = "ipv6_src"
    ipv6_dst = "ipv6_dst"
    nd_target = "nd_target"
    dl_src = "dl_src"
    dl_dst = "dl_dst"
    arp_sha = "arp_sha"
    arp_tha = "arp_tha"
    nd_sll = "nd_sll"
    nd_tll = "nd_tll"
    tcp_flags = "tcp_flags"
    actions = "actions"
    ip_frag = "ip_frag"
    tun_flags = "tun_flags"
    # TUN_METADATA
    # REG_ID
    # XREG_ID
    send_flow_rem = "send_flow_rem"
    check_overlap = "check_overlap"
    out_port = "out_port"
    out_group = "out_group"


class OF_ACTION(Enum):
    resubmit = "resubmit"
    note = "note"


class IntWithMask(int):

    def __new__(cls, *args, mask=None):
        self = super().__new__(cls, *args)
        self.mask = mask
        return self

    def __repr__(self):
        s = int.__repr__(self)
        if self.mask is None:
            return s
        else:
            return "%s/0x%x" % (s, self.mask)


class IPv6():

    def __init__(self, s):
        self.s = s

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.s == other.s

    def __hash__(self):
        return hash(self.s)

    def __repr__(self):
        return self.s


class IPv4():

    def __init__(self, s):
        self.s = s

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.s == other.s

    def __hash__(self):
        return hash(self.s)

    def __repr__(self):
        return self.s


class ETH_MAC():

    def __init__(self, s):
        self.s = s

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.s == other.s

    def __hash__(self):
        return hash(self.s)

    def __repr__(self):
        return self.s


class TCP_FLAG(Enum):
    fin = "fin"
    syn = "syn"
    rst = "rst"
    psh = "psh"
    ack = "ack"
    urg = "urg"
    ece = "ece"
    cwr = "cwr"
    ns = "ns"


MATCH_IGNORED_KEYS = {
    OF_RECORD_ITEM.cookie,
    OF_RECORD_ITEM.table,
    OF_RECORD_ITEM.duration,
    OF_RECORD_ITEM.n_packets,
    OF_RECORD_ITEM.n_bytes,
    OF_RECORD_ITEM.hard_timeout,
    OF_RECORD_ITEM.idle_timeout,
    OF_RECORD_ITEM.idle_age,
    OF_RECORD_ITEM.hard_age,
    OF_RECORD_ITEM.actions,
}
LPM_FIELDS = {
    OF_RECORD_ITEM.nw_src,
    OF_RECORD_ITEM.nw_dst,
    OF_RECORD_ITEM.arp_spa,
    OF_RECORD_ITEM.arp_tpa,
    OF_RECORD_ITEM.ipv6_dst,
    OF_RECORD_ITEM.ipv6_src,
    OF_RECORD_ITEM.dl_dst,
    OF_RECORD_ITEM.dl_src,
    OF_RECORD_ITEM.tp_dst,
    OF_RECORD_ITEM.tp_src,
    OF_RECORD_ITEM.tcp_src,
    OF_RECORD_ITEM.tcp_dst,
    OF_RECORD_ITEM.udp_src,
    OF_RECORD_ITEM.udp_dst,
    OF_RECORD_ITEM.vlan_tci,
    OF_RECORD_ITEM.sctp_src,
    OF_RECORD_ITEM.sctp_dst,
}
