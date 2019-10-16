from bisect import bisect
from copy import deepcopy
from multiprocessing import Pool
from pprint import pprint
from random import Random
from typing import List

from openflow_analysis.of_enums import OF_RECORD_ITEM, OF_ACTION, \
    MATCH_IGNORED_KEYS
from openflow_analysis.of_parser_utils import parse_of_flow_dump_file, \
    parse_of_flow_dump_lines
import sys


def copy_matching_items(trace, rule):
    for k, v in rule.items():
        if k in MATCH_IGNORED_KEYS or k == OF_RECORD_ITEM.priority:
            continue
        if k not in trace:
            trace[k] = deepcopy(v)


def build_trace_record(trace: dict, rules_in_table: List[dict],
                       current_table: int, rand: Random):
    table_rules = rules_in_table[current_table]
    if not table_rules:
        return

    packet_cnts = [r[OF_RECORD_ITEM.n_packets] for r in table_rules]
    sum_of_packets = sum(packet_cnts)
    probabilities = [c / sum_of_packets for c in packet_cnts]
    for i in range(len(probabilities)):
        if i > 0:
            probabilities[i] += probabilities[i - 1]

    rule_to_use_i = bisect(probabilities, rand.random())
    if rule_to_use_i == len(probabilities):
        rule_to_use_i -= 1
    rule = table_rules[rule_to_use_i]
    copy_matching_items(trace, rule)

    try:
        actions = rule[OF_RECORD_ITEM.actions]
    except KeyError:
        return
    resubmit = None
    for a in actions:
        if isinstance(a, tuple) and a[0] == OF_ACTION.resubmit:
            resubmit = a[1]
            break

    if resubmit is None:
        return
    elif isinstance(resubmit, int):
        build_trace_record(trace, rules_in_table, resubmit, rand)
    elif resubmit[1] is not None:
        build_trace_record(trace, rules_in_table, resubmit[1], rand)


def generate_traces(rules, n, rand):
    rules_filtered = [r for r in rules
                      if r[OF_RECORD_ITEM.n_packets] > 0]
    rules_in_table = {}
    # print(len(rules), len(rules_filtered))
    for r in rules_filtered:
        # print(r)
        t = r[OF_RECORD_ITEM.table]
        table_rules = rules_in_table.setdefault(t, [])
        table_rules.append(r)

    for _ in range(n):
        trace = {}
        build_trace_record(trace, rules_in_table, 0, rand)
        yield trace


def str_format_of_record(r):
    items = list(sorted(r.items(), key=lambda x: x[0].name))
    buff = []
    for k, v in items:
        if v is None:
            buff.append(k.name)
        else:
            buff.append("%s=%s" % (k.name, repr(v)))
    return ", ".join(buff)


if __name__ == "__main__":
    flow_file_name = sys.argv[0]
    with open(flow_file_name) as f:
        lines = f.readlines()
        lines = ["\n" if ("n_packets=0" in line) else line
                 for line in lines]

    rand = Random(0)
    with Pool() as pool:
        rules = parse_of_flow_dump_lines(lines, pool)
        seen = set()
        for t in generate_traces(rules, 100000, rand):
            if t:
                s = str_format_of_record(t)
                if s not in seen:
                    print(s)
                    seen.add(s)
