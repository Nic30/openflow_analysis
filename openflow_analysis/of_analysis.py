from pprint import pprint
import re
import sys
import urllib.request

from openflow_analysis.of_parser_utils import parse_of_flow_dump_file
from openflow_analysis.of_enums import IntWithMask, OF_ACTION, OF_RECORD_ITEM, \
    OF_REG, ETH_MAC, IPv4, IPv6
import os
from enum import Enum
import json
from multiprocessing import Pool

"""
This script produces informations about comlexity of OpenFlow ruleset. And .dot diagram of table dependencies.
Input is output of ovs ofctl dump flows command.
"""


def build_table_dependency_graph(data):
    table_deps = {}
    for rule in data:
        t = rule[OF_RECORD_ITEM.table]
        try:
            actions = rule[OF_RECORD_ITEM.actions]
        except KeyError:
            continue
        for a in actions:
            if a[0] == OF_ACTION.resubmit and isinstance(a[1], tuple):
                _, resubmit_table = a[1]
                if resubmit_table is not None:
                    deps = table_deps.setdefault(t, set())
                    deps.add(resubmit_table)

    return table_deps


def collect_table_keys(data, exclude):
    table_keys = {}
    for rule in data:
        t = rule[OF_RECORD_ITEM.table]
        for k in rule.keys():
            if k not in exclude:
                keys = table_keys.setdefault(t, set())
                keys.add(k)
    return table_keys


def collect_table_sizes(rules):
    """
    Count number of rules per table
    """
    table_size = {}
    for rule in rules:
        t = rule[OF_RECORD_ITEM.table]
        s = table_size.get(t, 0)
        s += 1
        table_size[t] = s
    return table_size


def collect_tale_uniq_rules(rules, IGNORED_KEYS):
    """
    Collect unique rules per table
    """

    def build_key(rule):
        values = [item for item in rule.items() if item[0] not in IGNORED_KEYS and item[0] != OF_RECORD_ITEM.tcp_flags]
        if OF_RECORD_ITEM.tcp_flags in rule:
            flags = rule[OF_RECORD_ITEM.tcp_flags]
            flags = [item for item in flags.items()]
            flags.sort(key=lambda item: item[0].name)
            values.append((OF_RECORD_ITEM.tcp_flags, tuple(flags)))
        values.sort(key=lambda item: item[0].name)
        return tuple(values)

    table_rules = {}
    for rule in rules:
        t = rule[OF_RECORD_ITEM.table]
        s = table_rules.get(t, set())
        k = build_key(rule)

        s.add(k)
        table_rules[t] = s

    return table_rules


def save_dot_graph(data, graph_name, file_name):
    with open(file_name, "w") as f:
        f.write("digraph " + graph_name + "{\n")
        for table, targets in data.items():
            for t in targets:
                f.write("\tT_%d -> T_%d;\n" % (table, t))
        f.write("}")


class TableNameQuery():

    def __init__(self, doc_url="http://www.openvswitch.org/support/dist-docs/ovn-northd.8.html"):
        doc = urllib.request.urlopen(doc_url).read().decode("utf-8")
        doc = doc.replace("<u>", "").replace("</u>", "").replace("<b>", "").replace("</b>", "")

        self.doc = doc
        # self.doc = html.fromstring(doc)

    def get_table_name(self, table_id):
        m = re.finditer(".*Table %d\:(.*)" % table_id, self.doc)
        for _m in m:
            return _m


def collect_table_lpm(rules, LPM_FIELDS):
    """
    Count unique prefix lengths for LPM_FIELDS
    """
    table_lpms = {}
    for rule in rules:
        t = rule[OF_RECORD_ITEM.table]
        table_lpm = table_lpms.get(t, {})
        table_lpms[t] = table_lpm

        for lpm_field in LPM_FIELDS:
            try:
                v = rule[lpm_field]
            except KeyError:
                continue

            if isinstance(v, IntWithMask) and v.mask is not None:
                lpm_k = v.mask
            else:
                lpm_k = -1

            lpm_field_rec = table_lpm.setdefault(lpm_field, {})

            lpm_cnt = lpm_field_rec.get(lpm_k, 0)
            lpm_field_rec[lpm_k] = lpm_cnt + 1

    return table_lpms


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
    OF_RECORD_ITEM.metadata,
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


def is_json_compatible(obj):
    return obj is None or isinstance(obj, (str, int, float, bool))

# class EnumEncoder(json.JSONEncoder):
#     def default(self, obj):
#         return json.JSONEncoder.default(self, obj)


def to_json_compatible(obj):
    if isinstance(obj, (Enum, OF_REG, ETH_MAC, IPv4, IPv6)):
        return repr(obj)

    if isinstance(obj, set):
        return [to_json_compatible(i) for i in obj]

    if isinstance(obj, list):
        return [to_json_compatible(i) for i in obj]

    if isinstance(obj, tuple):
        return tuple(to_json_compatible(i) for i in obj)

    if isinstance(obj, dict):
        _obj = {}
        for k, v in obj.items():
            if not is_json_compatible(k):
                k = repr(k)
            _obj[k] = to_json_compatible(v)
        return _obj

    return obj


def report_bundle0(flow_file_name, result_dir, pool):
    # tq = TableNameQuery()
    dep_graph_file_name = "dependency.dot"
    if result_dir is not None:
        os.makedirs(result_dir, exist_ok=True)
        dep_graph_file_name = os.path.join(result_dir, dep_graph_file_name)

    reports = {}
    rules = parse_of_flow_dump_file(flow_file_name, pool)
    if result_dir is None:
        print("Dependencies:")
    deps = build_table_dependency_graph(rules)
    save_dot_graph(deps, "dependency", dep_graph_file_name)
    reports["dependencies"] = deps
    if result_dir is None:
        print(deps)
        print("Table keys:")
    table_keys = collect_table_keys(rules, MATCH_IGNORED_KEYS)
    reports["table_keys"] = table_keys
    if result_dir is None:
        pprint(table_keys)
        print("Rules for table:")
    table_sizes = collect_table_sizes(rules)
    reports["table_sizes"] = table_sizes
    if result_dir is None:
        pprint(table_sizes)
        print("LPM groups per table per field")
    table_lpm = collect_table_lpm(rules, LPM_FIELDS)
    reports["table_lpm"] = table_lpm
    if result_dir is None:
        pprint(table_lpm)
        print("Unique rules for table:")
    uniq_vals = collect_tale_uniq_rules(rules, MATCH_IGNORED_KEYS)
    # reports["uniq_vals"] = uniq_vals
    uniq_vals_cnt = {k: len(v) for k, v in uniq_vals.items()}
    reports["uniq_vals_cnt"] = uniq_vals_cnt
    if result_dir is None:
        pprint(uniq_vals_cnt)
    else:
        with open(os.path.join(result_dir, "report.json"), "w") as f:
            reports = to_json_compatible(reports)
            json.dump(reports, f, indent=4)  # , cls=EnumEncoder


if __name__ == "__main__":
    if len(sys.argv) == 2:
        fn = sys.argv[1]
        with Pool() as pool:
            report_bundle0(fn, None, pool)
    else:
        try:
            from data.index import get_jobs
        except ImportError:
            raise AssertionError("Missing argument whic specifies openflow flow dump file")

        jobs = get_jobs()

        with Pool() as pool:
            for flow_file_name, result_dir in jobs:
                report_bundle0(flow_file_name, result_dir, pool)
