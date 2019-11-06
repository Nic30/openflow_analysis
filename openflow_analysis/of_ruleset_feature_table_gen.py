from fnmatch import fnmatch
import json
import os
import re
from typing import Set

from openflow_analysis.of_enums import OF_RECORD_ITEM, LPM_FIELDS


table_template = """\
\\begin{center}
\\begin{tabular}{ |c|c|c|c|c| }
\\hline
    \\textbf{Ruleset name} & \\textbf{Rules cnt.} & \\textbf{Max TSS tables.} & \\textbf{Max. unique rules per table} & \\textbf{Fields matched} & \\textbf{Field with max LPM groups} \\\\ \\hline
%s
\\end{tabular}
\\end{center}
"""

ROOT = os.path.join(os.path.dirname(__file__), "..", "reports")


def find_files(directory, pattern):
    for root, _, files in os.walk(directory):
        for basename in files:
            if fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def get_file_name(f):
    return os.path.splitext(os.path.basename(f))[0]


class NonCompatibleKeyItems(Exception):
    pass


PROTOCOLS = {
    "ip",
    "ipv6",
    "icmp",
    "icmp6",
    "tcp",
    "tcp6",
    "udp",
    "udp6",
    "sctp",
    "sctp6",
    "arp",
    "rarp",
    "mpls",
    "mplsm",
}


def table_key_extend(a, b):
    a_tuple = eval(a)  # should be only tuple of strings
    a_set = set(a_tuple)
    a_set.update(b)

    if len(a_set.intersection(PROTOCOLS)) > 1:
        raise NonCompatibleKeyItems()

    return tuple(sorted(a_set))


def _get_mfc_keys(j, t, possible_prefixes: Set[str], res, seen_tables):
    deps = j['dependencies'].get(str(t), [])
    keys = j["table_key_tuples"].get(str(t), [])
    possible_prefixes_after_this_table = set()
    assert possible_prefixes
    for k in keys:
        for prefix in possible_prefixes:
            try:
                new_k = table_key_extend(k, prefix)
            except NonCompatibleKeyItems:
                new_k = None

            if new_k is not None:
                res[new_k] = 0
                possible_prefixes_after_this_table.add(new_k)

    if not keys:
        possible_prefixes_after_this_table.update(possible_prefixes)

    print((t, len(possible_prefixes_after_this_table)))
    if t not in seen_tables:
        seen_tables.add(t)
        for next_t in deps:
            if next_t == t:
                continue
            _get_mfc_keys(j, next_t, possible_prefixes_after_this_table, res,
                          seen_tables)
    # for k in possible_prefixes_after_this_table:
    #     res[k] = 0


def get_mfc_keys(j):
    mfc_keys = {}
    possible_prefixes = set([tuple(),])
    seen_tables = set()
    _get_mfc_keys(j, 0, possible_prefixes, mfc_keys, seen_tables)
    return mfc_keys


def get_max_TSS_tables_cnt(j):
    mfc_keys = get_mfc_keys(j)

    # {key: lpm_group_cnt}
    # resolve accumulated_lpms
    accumulated_lpms = {}
    for lpms in j['table_lpm'].values():
        for k, groups in lpms.items():
            accumulated_lpms[k] = len(groups)
    # normalize accumulated_lpms key
    _accumulated_lpms = {}
    _re = re.compile(".*\.([a-zA-Z0-9_]+).*")
    for k, v in accumulated_lpms.items():
        if "<" in k:
            m = _re.match(k)
            k = m.group(1)
        _accumulated_lpms[k] = v
    accumulated_lpms = _accumulated_lpms
    _LPM_FIELDS = set(f.value for f in LPM_FIELDS)
    tss_tables = 0
    for k in mfc_keys.keys():
        k_multiplier = 1
        for p in k:
            if p not in _LPM_FIELDS:
                lpm_on_part = 1
            else:
                lpm_on_part = accumulated_lpms[p]
            k_multiplier *= lpm_on_part
        tss_tables += k_multiplier
    return tss_tables


def load_ruleset_params(root):
    for fn in find_files(root, "*.json"):
        name = fn.split("/")[-2]
        print(name)
        with open(fn) as f:
            j = json.load(f)
            sizes = j['sizes']
            total_rule_cnt = sizes['size']
            max_rules_per_table = max([table_size
                                       for (table_size, _) in sizes["table_sizes"].values()
                                       ])
            used_keys = set()
            for keys in j['table_keys'].values():
                used_keys.update(keys)

            max_lpm_field = None
            for lpms in j['table_lpm'].values():
                for field_name, lpm_groups in lpms.items():
                    if max_lpm_field is None or len(max_lpm_field[1]) < len(lpm_groups):
                        max_lpm_field = (field_name, lpm_groups)
            max_TSS_tables = get_max_TSS_tables_cnt(j)
            yield (name, total_rule_cnt, max_TSS_tables, max_rules_per_table, len(used_keys),
                   len(max_lpm_field[1]), max_lpm_field[0])


def format_data_to_table(root):
    # Ruleset name
    # Rules cnt.
    # Max. unique rules per table
    # Max. unique used rules per table
    # Fields matched
    # Max LPM groups per field
    records = list(load_ruleset_params(root))
    records.sort(key=lambda x: x[0])

    line_buff = []
    for (name, total_rule_cnt, max_TSS_tables, max_rules_per_table,
         used_keys_cnt, max_lpm, max_lpm_field) in records:
        _max_lpm_field = re.search("'([0-9a-zA-Z_]+)'", max_lpm_field)
        max_lpm_field = _max_lpm_field.group(1)
        max_lpm_field = max_lpm_field.replace("_", "\_")
        name = name.replace("_", "\_")
        line = f"    \\texttt{{{name}}}\t& {total_rule_cnt}\t& {max_TSS_tables}\t& {max_rules_per_table}\t& {used_keys_cnt}\t& \\texttt{{{max_lpm_field}}}: {max_lpm}\t\\\\ \\hline\n"
        line_buff.append(line)

    return table_template % "".join(line_buff)


if __name__ == "__main__":
    t = format_data_to_table(ROOT)
    print(t)
