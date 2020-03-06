

table_template = """\
\\begin{center}
\\begin{tabular}{ |c|c|c| }
\\hline
    \\textbf{Fields/flags used} & \\textbf{Rules cnt.} & \\textbf{Priorities} \\\\ \\hline
%s
\\end{tabular}
\\end{center}
"""


def texttt(t):
    t = t.replace("_", "\_")
    return f"\\texttt{{{t}}}"


def generate_table_key_latex_table(data):
    rows = []
    for k, v in data.items():
        k = eval(k)
        used_cnt, resubmits_to, priorities = eval(v)
        row = []
        fields = []
        for k_name in k:
            if k_name == "priority":
                continue
            fields.append(texttt(k_name))
        fields = ", ".join(fields)
        priorities = ", ".join([str(p) for p in sorted(priorities)])
        row = f"    {fields}\t& {used_cnt}\t& {priorities}\t\\\\ \\hline\n"
        rows.append(row)

    return table_template % ("".join(rows))


if __name__ == "__main__":
    DATA = {
        "('ip', 'metadata', 'nw_src', 'priority', 'reg9')": "(202, set(), {100})",
        "('ipv6', 'ipv6_src', 'metadata', 'priority')": "(101, set(), {100})",
        "('ip', 'metadata', 'nw_dst', 'priority')": "(140, set(), {100, 60})",
        "('ip', 'metadata', 'nw_src', 'priority')": "(39, set(), {100})",
        "('icmp6', 'icmp_code', 'icmp_type', 'metadata', 'nw_ttl', 'priority')": "(26, set(), {80, 90})",
        "('icmp6', 'icmp_code', 'icmp_type', 'ipv6_dst', 'metadata', 'priority')": "(101, {10}, {90})",
        "('icmp6', 'icmp_code', 'icmp_type', 'ipv6_dst', 'metadata', 'nd_target', 'nw_ttl', 'priority', 'reg14')": "(176, set(), {90})",
        "('dl_src', 'ip', 'metadata', 'nw_src', 'priority', 'reg14')": "(28, {10}, {90})",
        "('dl_src', 'metadata', 'nw_dst', 'nw_src', 'priority', 'reg14', 'tp_dst', 'tp_src', 'udp')": "(28, {10}, {90})",
        "('arp', 'arp_op', 'arp_spa', 'arp_tpa', 'metadata', 'priority', 'reg14')": "(88, {32}, {90})",
        "('icmp', 'icmp_code', 'icmp_type', 'metadata', 'nw_dst', 'priority')": "(101, {10}, {90})",
        "('arp', 'arp_op', 'metadata', 'priority')": "(13, set(), {90})",
        "('arp', 'arp_op', 'arp_spa', 'metadata', 'priority', 'reg14')": "(88, set(), {80})",
        "('dl_src', 'ip', 'metadata', 'priority', 'reg14')": "(28, set(), {80})",
        "('dl_src', 'ipv6', 'metadata', 'priority', 'reg14')": "(28, set(), {80})",
        "('ipv6', 'ipv6_dst', 'metadata', 'priority')": "(101, set(), {60})",
        "('dl_dst', 'metadata', 'priority')": "(13, set(), {50})",
        "('ip', 'metadata', 'nw_frag', 'nw_ttl', 'priority', 'reg14')": "(202, set(), {40})",
        "('ip', 'metadata', 'nw_ttl', 'priority')": "(26, set(), {30})",
        "('metadata', 'priority')": "(102, {10}, {0})"
    }
    #DATA = {
    #        "('ip', 'metadata', 'reg6')": "(3, set(), set())",
    #        "('dl_dst', 'icmp', 'icmp_type', 'metadata', 'nw_dst', 'priority', 'reg2')": "(10, set(), {36887})",
    #        "('dl_dst', 'metadata', 'nw_dst', 'priority', 'reg2', 'tcp', 'tp_dst')": "(124, set(), {36892})",
    #        "('dl_dst', 'metadata', 'nw_dst', 'priority', 'reg2', 'tp_dst', 'udp')": "(134, set(), {36892})",
    #        "('arp', 'arp_op', 'metadata', 'priority', 'reg1', 'reg2', 'reg4')": "(1, set(), {32769})",
    #        "('priority', 'reg1', 'reg4')": "(60, set(), {32765, 32766})",
    #        "('metadata', 'reg6')": "(6, set(), set())",
    #        "('metadata', 'priority')": "(89, {1}, {36865, 32769, 32767})",
    #        "('metadata',)": "(51, {16}, set())",
    #        "('metadata', 'reg3')": "(57, {17}, set())",
    #        "('ip', 'metadata', 'nw_src', 'priority')": "(3, set(), {36996})",
    #        "('metadata', 'priority', 'reg2')": "(40, set(), {36864, 36865, 36903, 36905, 36883})",
    #        "('metadata', 'reg2')": "(8, {16}, set())",
    #        "('reg2',)": "(19, {18}, set())",
    #        "('metadata', 'priority', 'reg1', 'reg4')": "(23, set(), {32769, 36866, 36865})",
    #        "('metadata', 'priority', 'reg4')": "(21, set(), {36865})",
    #        "('ip', 'metadata', 'priority')": "(1, set(), {32769})",
    #        "('ip', 'metadata')": "(1, set(), set())",
    #        "('metadata', 'nw_dst', 'priority', 'tp_dst', 'tp_src', 'udp')": "(71, set(), {32897})",
    #        "('dl_dst', 'icmp', 'icmp_code', 'icmp_type', 'metadata', 'nw_dst', 'nw_src', 'priority', 'reg2')": "(724, set(), {36893})",
    #        "('ip', 'metadata', 'nw_dst', 'priority')": "(81, set(), {32896, 32773, 32789, 32792, 32793, 32799})",
    #        "('arp', 'arp_op', 'dl_dst', 'metadata', 'reg3')": "(3, set(), set())",
    #        "('dl_dst', 'metadata')": "(432, set(), set())",
    #        "('metadata', 'reg2', 'reg4')": "(396, set(), set())",
    #        "('dl_dst', 'metadata', 'nw_dst', 'priority', 'reg2', 'tp_dst', 'tp_src', 'udp')": "(10, set(), {36888})",
    #        "('dl_dst', 'icmp', 'icmp_code', 'icmp_type', 'metadata', 'nw_dst', 'priority', 'reg2')": "(14, set(), {36888, 36893})",
    #        "('dl_dst', 'ip', 'metadata', 'nw_dst', 'nw_src', 'priority', 'reg2')": "(724, set(), {36885})",
    #        "('arp', 'arp_op', 'dl_dst', 'metadata')": "(1, set(), set())",
    #        "('metadata', 'priority', 'reg1')": "(512, set(), {36864, 34817, 36865, 36903, 36883, 32767})",
    #        "('metadata', 'reg1')": "(48, {16}, set())",
    #        "('dl_dst', 'metadata', 'nw_dst', 'nw_src', 'priority', 'reg2', 'udp')": "(724, set(), {36891})",
    #        "('dl_dst', 'metadata', 'nw_dst', 'nw_src', 'priority', 'reg2', 'tcp')": "(724, set(), {36891})",
    #        "('arp', 'arp_sha', 'arp_spa', 'dl_src', 'metadata', 'priority', 'reg1')": "(26, set(), {36906})",
    #        "('arp', 'arp_op', 'dl_dst', 'metadata', 'priority', 'reg1')": "(1, set(), {32770})",
    #        "('arp', 'arp_op', 'arp_tpa', 'metadata', 'priority', 'reg1')": "(1, set(), {32770})",
    #        "('dl_src', 'icmp', 'icmp_type', 'metadata', 'nw_src', 'priority', 'reg1')": "(10, set(), {36887})",
    #        "('dl_src', 'icmp', 'icmp_code', 'icmp_type', 'metadata', 'nw_src', 'priority', 'reg1')": "(20, set(), {36888, 36893})",
    #        "('metadata', 'reg4')": "(28, set(), set())",
    #        "('metadata', 'reg7')": "(7, set(), set())",
    #        "('dl_src', 'metadata', 'nw_src', 'priority', 'reg1', 'tcp')": "(10, set(), {36891})",
    #        "('dl_src', 'metadata', 'nw_src', 'priority', 'reg1', 'udp')": "(23, set(), {36906, 36891})",
    #        "('dl_src', 'ip', 'metadata', 'nw_src', 'priority', 'reg1')": "(26, set(), {36904, 36885})",
    #        "('arp', 'dl_dst', 'metadata', 'priority', 'reg2')": "(13, set(), {36904})",
    #        "('metadata', 'priority', 'tun_id')": "(20, set(), {36867})",
    #        "('reg2', 'reg4')": "(19, {17}, set())",
    #        "('arp', 'arp_op', 'metadata', 'reg3')": "(4, set(), set())",
    #        "('dl_src', 'metadata', 'priority', 'reg1')": "(2, set(), {36865})",
    #        "('arp', 'dl_dst', 'metadata', 'priority', 'reg1')": "(1, set(), {32769})",
    #        "('metadata', 'pkt_mark', 'priority', 'reg1')": "(22, {16}, {36866})",
    #        "('arp', 'arp_tpa', 'dl_dst', 'metadata', 'priority', 'reg2')": "(26, set(), {36904})",
    #        "('dl_dst', 'ip', 'metadata', 'nw_dst', 'priority', 'reg2')": "(16, set(), {36904})",
    #        "('arp', 'arp_op', 'metadata')": "(2, set(), set())",
    #        "('arp', 'arp_op', 'dl_dst', 'metadata', 'priority')": "(2, set(), {32771})",
    #        "('metadata', 'priority', 'reg1', 'reg2')": "(10, set(), {37264})",
    #        "('dl_dst', 'icmp', 'metadata', 'nw_dst', 'priority', 'reg2')": "(4, set(), {36886})",
    #        "('metadata', 'priority', 'reg2', 'reg4')": "(20, set(), {36865})",
    #        "('metadata', 'reg1', 'reg5')": "(1, set(), set())",
    #        "('metadata', 'reg3', 'reg4')": "(6, set(), set())"
    #    }
    print(generate_table_key_latex_table(DATA))
