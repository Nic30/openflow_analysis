from enum import Enum
import json
from multiprocessing import Pool
import os
from pprint import pprint
import sys

from openflow_analysis.of_analysis import collect_table_lpm, \
    build_table_dependency_graph, save_dot_graph, collect_table_sizes, \
    collect_table_keys, collect_tale_uniq_rules, collect_table_key_tuples
from openflow_analysis.of_enums import LPM_FIELDS, OF_RECORD_ITEM, \
    MATCH_IGNORED_KEYS, OF_REG, ETH_MAC, IPv4, IPv6
from openflow_analysis.of_parser_utils import parse_of_flow_dump_file


# class EnumEncoder(json.JSONEncoder):
#     def default(self, obj):
#         return json.JSONEncoder.default(self, obj)
def is_json_compatible(obj):
    return obj is None or isinstance(obj, (str, int, float, bool))


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
        print("Table keys:")
    table_keys = collect_table_keys(rules, MATCH_IGNORED_KEYS)
    reports["table_keys"] = table_keys
    if result_dir is None:
        pprint(table_keys)

    if result_dir is None:
        print("Table key tuples:")
    table_key_tuples = collect_table_key_tuples(rules, MATCH_IGNORED_KEYS)
    reports["table_key_tuples"] = table_key_tuples
    if result_dir is None:
        pprint(table_key_tuples)

    if result_dir is None:
        print("Rules for table:")
    table_sizes = collect_table_sizes(rules)
    used_rules = [r for r in rules if r[OF_RECORD_ITEM.n_packets] > 0]
    reports["sizes"] = {
        "size": len(rules),
        "used": len(used_rules),
        "table_sizes": table_sizes
    }
    if result_dir is None:
        pprint(table_sizes)
        print("Dependencies:")

    deps = build_table_dependency_graph(rules)
    save_dot_graph(deps, table_sizes, "dependency", dep_graph_file_name)
    reports["dependencies"] = deps
    if result_dir is None:
        print(deps)
        print("LPM groups per table per field")
    table_lpm = collect_table_lpm(rules, LPM_FIELDS)
    reports["table_lpm"] = table_lpm
    if result_dir is None:
        pprint(table_lpm)
        print("Size of ruleset")

    if result_dir is None:
        pprint(reports["sizes"])
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
