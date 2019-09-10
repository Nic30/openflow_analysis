from antlr4 import CommonTokenStream
from antlr4.FileStream import FileStream
from antlr4.error.ErrorListener import ConsoleErrorListener

from openflow_analysis.of_enums import OF_RECORD_ITEM, TCP_FLAG, \
    IntWithMask, OF_ACTION, ETH_MAC, IPv4, IPv6, OF_REG
from openflow_analysis.openflowLexer import openflowLexer
from openflow_analysis.openflowParser import openflowParser


class MyErrorListener(ConsoleErrorListener):

    def __init__(self):
        super(MyErrorListener, self).__init__()

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        super(MyErrorListener, self).syntaxError(recognizer, offendingSymbol, line, column, msg, e)
        raise Exception()


def load_ast_file(file):
    return load_ast_by_file_name(file.name)


def load_ast_by_file_name(fname):
    f = FileStream(fname, encoding="utf-8")
    lexer = openflowLexer(f)
    stream = CommonTokenStream(lexer)
    parser = openflowParser(stream)
    parser.addErrorListener(MyErrorListener())
    tree = parser.openflow_dump_text()
    return tree


def parse_of_record_tcp_flags(ctx):
    # tcp_flag_item:
    #     (PLUS | MINUS)? (
    #      KW_TCP_FLAG_fin
    #      | KW_TCP_FLAG_syn
    #      | KW_TCP_FLAG_rst
    #      | KW_TCP_FLAG_psh
    #      | KW_TCP_FLAG_ack
    #      | KW_TCP_FLAG_urg
    #      | KW_TCP_FLAG_ece
    #      | KW_TCP_FLAG_cwr
    #      | KW_TCP_FLAG_ns
    #     );
    # of_record_tcp_flags:
    #   KW_tcp_flags EQ (
    #      BASED_HEX_NUM
    #      | (tcp_flag_item)+
    #   );
    val = ctx.BASED_HEX_NUM()
    if val is not None:
        return (OF_RECORD_ITEM.tcp_flags, parse_BASED_HEX_NUM(val))

    val = {}
    for i in ctx.tcp_flag_item:
        if len(i.children) == 2:
            v = i.children[0].symbol.text
            k = TCP_FLAG(i.children[1].symbol.text)
        else:
            k = TCP_FLAG(i.children[0].symbol.text)
            v = None
        val[k] = v

    return (OF_RECORD_ITEM.tcp_flags, val)


def parse_of_record_protocol(ctx):
    return (OF_RECORD_ITEM(ctx.children[0].symbol.text), None)


def parse_of_actions(ctx):
    """
    of_actions: KW_actions EQ of_action_item (COMMA of_action_item)*;
    """
    res = []
    for o in ctx.of_action_item():
        item = parse_of_action_item(o)
        if item == (None, None):
            continue
        res.append(item)
    return (OF_RECORD_ITEM.actions, res)


def parse_of_action_item(ctx):
    of_action_resubmit = ctx.of_action_resubmit()
    if of_action_resubmit is not None:
        return parse_of_action_resubmit(of_action_resubmit)

    # print("parse_of_action_item")
    return None, None


def parse_of_action_resubmit(ctx):
    """
    of_action_resubmit:
      KW_resubmit (COLON optionaly_masked_int
                   | LPAREN (optionaly_masked_int)?
                     COMMA (DEC_NUM)?
                     (COMMA KW_ct)? RPAREN) // ct added for ruleset from vmware
     ;
    """
    k = OF_ACTION.resubmit
    optionaly_masked_int = ctx.optionaly_masked_int()
    if optionaly_masked_int is not None:
        optionaly_masked_int = parse_optionaly_masked_int(optionaly_masked_int)
    if ctx.COLON():
        return (k, optionaly_masked_int)
    else:
        v0 = optionaly_masked_int
        v1 = ctx.DEC_NUM()
        if v1 is not None:
            v1 = parse_DEC_NUM(v1)
        return (k, (v0, v1))


def parse_of_record_item(ctx):
    """
    KW_duration EQ TIME_NUM
     | ( 
         KW_in_port
         | KW_dl_vlan
         | KW_dl_vlan_pcp
         | KW_dl_type
         | KW_nw_proto
         | KW_ip_proto
         | KW_nw_tos
         | KW_ip_dscp
         | KW_nw_ecn
         | KW_ip_ecn
         | KW_nw_ttl
         | KW_icmp_type
         | KW_icmp_code
         | KW_table
         | KW_ipv6_label
         | KW_mpls_bos
         | KW_mpls_tc
         | KW_ct_zone
         | KW_n_packets
         | KW_n_bytes
         | KW_idle_age
         | KW_hard_age
         | KW_priority
         | KW_arp_op
         | KW_idle_timeout
         | KW_hard_timeout
         | KW_importance
        ) EQ DEC_NUMTIME_NUM
     | (
         KW_cookie
        | KW_vlan_tci
        | KW_tcp_src
        | KW_tcp_dst
        | KW_udp_src
        | KW_udp_dst
        | KW_sctp_src
        | KW_sctp_dst
        | KW_tp_dst
        | KW_tp_src
        | KW_mpls_label
        | KW_tun_id
        | KW_tunnel_id
        | KW_tun_gbp_id
        | KW_tun_gbp_flags
        | REG_ID
        | XREG_ID
        | KW_pkt_mark
        | KW_actset_output
        | KW_conj_id
        | KW_ct_mark
        | KW_ct_label
        | KW_metadata
        ) EQ optionaly_masked_int
     | KW_ct_state EQ (optionaly_masked_int | (ct_state_item)+)
     | (
        KW_nw_src
        | KW_nw_dst
        | KW_arp_spa
        | KW_arp_tpa
        | KW_tun_src
        | KW_tun_dst
        ) EQ IPv4
     | (KW_ipv6_src
        | KW_ipv6_dst
        | KW_nd_target
        ) EQ IPv6
     | (KW_dl_src
        | KW_dl_dst
        | KW_arp_sha
        | KW_arp_tha
        | KW_nd_sll
        | KW_nd_tll
        ) EQ ETH_MAC
     | of_record_tcp_flags
     | of_record_protocol
     | of_actions
     | KW_ip_frag EQ frag_type
     | KW_tun_flags EQ (PLUS | MINUS) KW_oam
     | TUN_METADATA (EQ optionaly_masked_int)
     | KW_send_flow_rem
     | KW_check_overlap
     | KW_out_port EQ optionaly_masked_int
     | KW_out_group EQ optionaly_masked_int
    ;
    """
    try:
        kw_text = ctx.children[0].symbol.text
    except AttributeError:
        kw_text = None
    if kw_text is None:
        of_record_tcp_flags = ctx.of_record_tcp_flags()
        if of_record_tcp_flags is not None:
            return parse_of_record_tcp_flags(of_record_tcp_flags)
        of_record_protocol = ctx.of_record_protocol()
        if of_record_protocol is not None:
            return parse_of_record_protocol(of_record_protocol)
        of_actions = ctx.of_actions()
        if of_actions is not None:
            return parse_of_actions(of_actions)
        raise NotImplementedError()

    try:
        kw_text = OF_RECORD_ITEM(kw_text)
    except ValueError:
        kw_text = OF_REG(kw_text)

    val = ctx.DEC_NUM()
    if val is not None:
        return (kw_text, parse_DEC_NUM(val))
    val = ctx.optionaly_masked_int()
    if val is not None:
        return (kw_text, parse_optionaly_masked_int(val))
    val = ctx.TIME_NUM()
    if val is not None:
        return (kw_text, parse_TIME_NUM(val))
    val = ctx.ETH_MAC()
    if val is not None:
        return (kw_text, parse_ETH_MAC(val))
    val = ctx.IPv4()
    if val is not None:
        return (kw_text, parse_IPv4(val))
    val = ctx.IPv6()
    if val is not None:
        return (kw_text, parse_IPv6(val))
    if kw_text == OF_RECORD_ITEM.ct_state:
        return (kw_text, None)
    raise NotImplementedError(kw_text)


def parse_ETH_MAC(ctx):
    t = ctx.symbol.text
    return ETH_MAC(t)


def parse_IPv4(ctx):
    t = ctx.symbol.text
    return IPv4(t)


def parse_IPv6(ctx):
    t = ctx.symbol.textxid
    return IPv6(t)


def parse_TIME_NUM(ctx):
    t = ctx.symbol.text
    assert t.endswith("s")
    return float(t[:-1])


def parse_optionaly_masked_int(ctx):
    """
    optionaly_masked_int:
      DEC_NUM
      | BASED_HEX_NUM
    ;
    """
    v = ctx.DEC_NUM()
    if v is not None:
        return parse_DEC_NUM(v)
    v = ctx.BASED_HEX_NUM()
    return parse_BASED_HEX_NUM(v)


def parse_BASED_HEX_NUM(ctx):
    v = ctx.symbol.text.split("/")
    if len(v) == 1:
        return int(v[0], 16)
    else:
        return IntWithMask(int(v[0], 16), mask=int(v[1], 16))


def parse_DEC_NUM(ctx):
    return int(ctx.symbol.text)


def parse_of_record(ctx):
    res = {}
    for item in ctx.of_record_item():
        k, v = parse_of_record_item(item)
        res[k] = v
    return res


def parse_BYTE_STRING(ctx):
    text = ctx.symbol.text
    chr_seq = map(lambda x: bytes(chr(int(x, 16)), encoding="utf-8"),
                  text.split("."))
    return b"".join(list(chr_seq))


def parse_of_flow_dump_file(file_name):
    tree = load_ast_by_file_name(file_name)
    for o in tree.of_record():
        yield parse_of_record(o)


if __name__ == '__main__':
    # fname = "../data/example0.txt"
    fname = "data/openflow_rules-Jacob_Cherkas-VMware/flows-2015-07-03_formatted"

    for rec in parse_of_flow_dump_file(fname):
        print(rec)
