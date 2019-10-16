"""
This script produces informations about comlexity of OpenFlow ruleset
and a .dot diagram of table dependencies.
Input is output of ovs ofctl dump flows command.
"""

from openflow_analysis.of_enums import IntWithMask, OF_ACTION, OF_RECORD_ITEM


def get_resubmit_tables(rule):
    resubmits = []
    try:
        actions = rule[OF_RECORD_ITEM.actions]
    except KeyError:
        return resubmits
    for a in actions:
        if a[0] == OF_ACTION.resubmit and isinstance(a[1], tuple):
            _, resubmit_table = a[1]
            if resubmit_table is not None:
                resubmits.append(resubmit_table)
    return resubmits


def build_table_dependency_graph(data):
    """
    :return: dict {table_id: [ resubmits to table ids ]}
    """
    table_deps = {}
    for rule in data:
        t = rule[OF_RECORD_ITEM.table]
        for resubmit_table in get_resubmit_tables(rule):
            deps = table_deps.setdefault(t, set())
            deps.add(resubmit_table)

    return table_deps


def collect_table_keys(data, exclude):
    """
    Resolve used fields per table
    """
    table_keys = {}
    for rule in data:
        t = rule[OF_RECORD_ITEM.table]
        for k in rule.keys():
            if k not in exclude:
                keys = table_keys.setdefault(t, set())
                keys.add(k)
    return table_keys


class KeyTupleStats():

    def __init__(self):
        self.used_cnt = 0
        self.resubmits_to = set()
        self.priorities = set()

    def __repr__(self):
        return "(%d, %r, %r)" % (self.used_cnt, self.resubmits_to, self.priorities)


def collect_table_key_tuples(data, exclude):

    # dict {table:{key_tuple: KeyTupleStats instance}}
    def build_key(rule):
        keys = []
        for k in rule.keys():
            if k not in exclude:
                keys.append(k)
        keys = tuple(sorted(map(lambda x: x.name, keys)))
        return keys

    table_key_tuples = {}
    for rule in data:
        t = rule[OF_RECORD_ITEM.table]
        table_keys = table_key_tuples.setdefault(t, {})
        keys_used = build_key(rule)
        stats = table_keys.setdefault(keys_used, KeyTupleStats())
        stats.used_cnt += 1
        resubmits_to = get_resubmit_tables(rule)
        stats.resubmits_to.update(resubmits_to)
        try:
            prio = rule[OF_RECORD_ITEM.priority]
            stats.priorities.add(prio)
        except KeyError:
            pass

    return table_key_tuples


def collect_table_sizes(rules):
    """
    Count number of rules per table

    :return: dict {table_id: [records, records with n_packets > 0]}
    """
    table_size = {}
    for rule in rules:
        t = rule[OF_RECORD_ITEM.table]
        s = table_size.get(t, [0, 0])
        s[0] += 1
        if rule[OF_RECORD_ITEM.n_packets] > 0:
            s[1] += 1

        table_size[t] = s

    return table_size


def collect_tale_uniq_rules(rules, IGNORED_KEYS):
    """
    Collect unique rules per table
    """

    def build_key(rule):
        values = [item for item in rule.items()
                  if item[0] not in IGNORED_KEYS
                  and item[0] != OF_RECORD_ITEM.tcp_flags]

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


def save_dot_graph(data, size_of_tables, graph_name, file_name):
    with open(file_name, "w") as f:
        f.write("digraph " + graph_name + "{\n")
        all_tables = set()
        for table, targets in data.items():
            all_tables.add(table)
            all_tables.update(targets)

        for table in all_tables:
            size = size_of_tables.get(table, 0)
            f.write(f'\tT_{table} [label="Table<{table}> size:{size}"];\n')
        for table, targets in data.items():
            for t in targets:
                f.write("\tT_%d -> T_%d;\n" % (table, t))
        f.write("}")


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
                if lpm_field is OF_RECORD_ITEM.vlan_tci:
                    if lpm_k == 12:
                        lpm_k = -1
            else:
                lpm_k = -1

            lpm_field_rec = table_lpm.setdefault(lpm_field, {})

            lpm_cnt = lpm_field_rec.get(lpm_k, 0)
            lpm_field_rec[lpm_k] = lpm_cnt + 1

    return table_lpms
