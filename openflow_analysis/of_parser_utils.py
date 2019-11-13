from antlr4 import CommonTokenStream
from antlr4.InputStream import InputStream
from antlr4.error.ErrorListener import ConsoleErrorListener
from math import ceil
from multiprocessing import Pool

from openflow_analysis.of_enums import OF_RECORD_ITEM, TCP_FLAG, \
    IntWithMask, OF_ACTION, ETH_MAC, IPv4, IPv6, OF_REG
from openflow_analysis.openflowLexer import openflowLexer
from openflow_analysis.openflowParser import openflowParser


class MyErrorListener(ConsoleErrorListener):

    def __init__(self):
        super(MyErrorListener, self).__init__()

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        super(MyErrorListener, self).syntaxError(
            recognizer, offendingSymbol, line, column, msg, e)
        raise Exception(recognizer.getInputStream().getText().split('\n')[line])


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
    for i in ctx.tcp_flag_item():
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
    resubmit = ctx.of_action_resubmit()
    if resubmit is not None:
        return parse_of_action_resubmit(resubmit)
    note = ctx.of_action_note()
    if note is not None:
        return parse_note(note)

    # print("parse_of_action_item")
    return None, None


def parse_note(ctx):
    t = ctx.BYTE_STRING()
    b = parse_BYTE_STRING(t)
    return (OF_ACTION.note, b)


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
        ) EQ optionaly_masked_int
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
        ) EQ BYTE_STRING
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
     | ( KW_ip_frag | KW_nw_frag ) EQ frag_type
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

    val = ctx.optionaly_masked_int()
    if val is not None:
        return (kw_text, parse_optionaly_masked_int(val))
    val = ctx.TIME_NUM()
    if val is not None:
        return (kw_text, parse_TIME_NUM(val))
    val = ctx.COLON_SEPARATED_HEX_ADDR()
    if val is not None:
        if ctx.KW_ipv6_src() is not None\
                or ctx.KW_ipv6_dst is not None\
                or ctx.KW_nd_target() is not None:
            return (kw_text, parse_IPv6(val))
        else:
            return (kw_text, parse_ETH_MAC(val))

    val = ctx.BYTE_STRING()
    if val is not None:
        return (kw_text, parse_IPv4(val))

    val = ctx.frag_type()
    if val is not None:
        return (kw_text, parse_frag_type(val))

    if kw_text == OF_RECORD_ITEM.ct_state:
        return (kw_text, None)

    raise NotImplementedError(kw_text)


def parse_frag_type(ctx):
    # [TODO]
    return None


def parse_ETH_MAC(ctx):
    t = ctx.symbol.text
    return ETH_MAC(t)


def parse_IPv4(ctx):
    t = ctx.symbol.text
    return IPv4(t)


def parse_IPv6(ctx):
    t = ctx.symbol.text
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
    b = text.split(".")
    b = [int(x, 16) for x in b]
    b = bytes(b)
    return b


def parse_openflow_dump_text(ctx):
    res = []
    for o in ctx.of_record():
        r = parse_of_record(o)
        res.append(r)
    return res


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def load_ast_from_str(data):
    f = InputStream(data)
    lexer = openflowLexer(f)
    lexer.addErrorListener(MyErrorListener())
    stream = CommonTokenStream(lexer)
    parser = openflowParser(stream)
    parser.addErrorListener(MyErrorListener())
    tree = parser.openflow_dump_text()
    return tree


def load_ast_from_str_wrap(args):
    data_lines, offset, parse_fn = args
    data = "".join([*['\n' for _ in range(offset)], *data_lines])
    # print(offset, len(data_lines), len(data.split("\n")))
    ast = load_ast_from_str(data)
    parsed = parse_fn(ast)
    return parsed


def parse_lines(lines, parse_fn, pool):
    workers = pool._processes
    if workers > 1:
        jobs = [[x, 0, parse_fn]
                for x in chunks(lines, ceil(len(lines) / workers) + 1)]
        # prepend newlines to make line numbering consystent
        offset = 0
        for j in jobs:
            j[1] = offset
            offset += len(j[0])
        assert offset == len(lines)
    else:
        jobs = (lines, 0, parse_fn)

    res_data = pool.map(load_ast_from_str_wrap, jobs)

    res = []
    for d in res_data:
        res.extend(d)
    return res


def parse_by_file_name(fname, parse_fn, pool):
    # f = FileStream(fname, encoding="utf-8")
    with open(fname) as f:
        lines = f.readlines()
    return parse_lines(lines, parse_fn, pool)


def parse_of_flow_dump_lines(lines, pool):
    return parse_lines(lines, parse_openflow_dump_text, pool)


def parse_of_flow_dump_file(file_name, pool):
    return parse_by_file_name(file_name, parse_openflow_dump_text, pool)


class DummyPool():

    def __init__(self):
        self._processes = 1

    def map(self, iterable, fn):
        return map(iterable, fn)


if __name__ == '__main__':
    fname = "../data/example0.txt"
    fname = "/home/nic30/Documents/workspace/openflow_analysis/data/openflow_rules-Jacob_Cherkas-VMware/flows-2015-06-18_formatted"

    with Pool() as pool:
        for rec in parse_of_flow_dump_file(fname, pool):
            if rec[OF_RECORD_ITEM.table] != 1:
                continue

            try:
                act = rec[OF_RECORD_ITEM.actions]
            except KeyError:
                continue

            for a in act:
                if isinstance(a, tuple) and a[0] == OF_ACTION.note:
                    print(rec)
