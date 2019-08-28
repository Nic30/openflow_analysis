import glob
import re
from pprint import pprint
import sys
import urllib.request
# from lxml import html

files = [f for f in glob.glob("./**/flows*", recursive=True)]

RE_KV_PAIR = re.compile("\s*([A-Za-z0-9_]+)(=[^=]+)?(?=((,\s*)|(\s+)[A-Za-z0-9_]+=)|$),?")
# id:value or id(val, ....)
RE_ACTION_ITEM = re.compile("([^,()]+)(\(([^,()]*,)*([^,()]+)\))?(,|$)")


def notes_as_bytes(note):
    chr_seq = map(lambda x: bytes(chr(int(x, 16)), encoding="utf-8"), note.split("."))
    return "note:" + repr(b"".join(list(chr_seq)))


def parse_actions(s):
    action = {}
    start = 0
    while True:
        m = RE_ACTION_ITEM.match(s, start)
        if m is None:
            break
        start = m.end()
        item = m.group(1)
        item = item.split(":")
        if len(item) == 2:
            k, v = item
        else:
            k, v = m.group(1), m.group(2)
        if k == "note":
            v = notes_as_bytes(v)
        action[k] = v
    return action


def process_of_line(l):
    rule = {}
    start = 0
    while True:
        m = RE_KV_PAIR.match(l, start)
        if m is None:
            break
        k = m.group(1)
        v = m.group(2).strip()
        if v.startswith("="):
            v = v[1:]
        if v.endswith(","):
            v = v[:-1]
        if k == "actions":
            v = parse_actions(v)
        rule[k] = v
        start = m.end()
    return rule


def convert_file(fn):
    rules = []
    with open(fn) as f:
        is_py_array = f.read(1) == "["
    if is_py_array:
        with open(fn) as f:
            d = f.read()
            data = eval(d)
            for l in data[1:]:
                rule = process_of_line(l)
                if rule == {}:
                    print(l)
                    continue
                rules.append(rule)

    else:
        with open(fn) as f:
            for l in f:
                rule = process_of_line(l)
                if rule == {}:
                    print(l)
                    continue
                rules.append(rule)

    return rules


def build_table_dependency_graph(data):
    table_deps = {}
    for rule in data:
        t = rule["table"]

        try:
            resubmit = rule['actions']['resubmit']
        except KeyError:
            continue
        deps = table_deps.get(t, set())
        table_deps[t] = deps
        deps.add(resubmit)

    return table_deps


def collect_table_keys(data, exclude):
    table_keys = {}
    for rule in data:
        t = rule['table']
        for k in rule.keys():
            if k not in exclude:
                keys = table_keys.get(t, set())
                keys.add(k)
                table_keys[t] = keys
    return table_keys


def collect_table_sizes(rules):
    """
    Count number of rules per table
    """
    table_size = {}
    for rule in rules:
        t = rule['table']
        s = table_size.get(t, 0)
        s += 1
        table_size[t] = s
    return table_size


def collect_tale_uniq_rules(data, IGNORED_KEYS):
    """
    Collect unique rules per table
    """

    def build_key(rule):
        values = [item for item in rule.items() if item[0] not in IGNORED_KEYS]
        values.sort(key=lambda item: item[0])
        return tuple(values)

    table_rules = {}
    for rule in rules:
        t = rule['table']
        s = table_rules.get(t, set())
        s.add(build_key(rule))
        table_rules[t] = s

    return table_rules


def save_dot_graph(data, graph_name, file_name):
    with open(file_name, "w") as f:
        f.write("digraph " + graph_name + "{\n")
        for table, targets in data.items():
            for targ in targets:
                targ = targ.replace("(", " ").replace(",", " ").replace(")", " ")
                targ = targ.split()
                for t in targ:
                    if t:
                        f.write("\tT_" + table + " -> T_" + t + ";\n")
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
        t = rule['table']
        table_lpm = table_lpms.get(t, {})
        table_lpms[t] = table_lpm

        for lpm_field in LPM_FIELDS:
            try:
                v = rule[lpm_field]
            except KeyError:
                continue

            v = v.split("/")
            if len(v) == 2:
                _, lpm_k = v
            else:
                lpm_k = -1

            lpm_field_rec = table_lpm.get(lpm_field, {})
            table_lpm[lpm_field] = lpm_field_rec

            lpm_cnt = lpm_field_rec.get(lpm_k, 0)
            lpm_field_rec[lpm_k] = lpm_cnt + 1

    return table_lpms

# [TODO] how to dump Modify State Messages (which we have)
# [TODO] how to dump rules form ovn-northd


if __name__ == "__main__":
    tq = TableNameQuery()
    assert len(sys.argv) == 2
    fn = sys.argv[1]

    rules = convert_file(fn)
    print("Dependencies:")
    deps = build_table_dependency_graph(rules)
    save_dot_graph(deps, "dependency", "dependency.dot")

    print(deps)
    IGNORED_KEYS = {"cookie", "table", 'duration',
                    'n_packets', 'n_bytes', 'hard_timeout',
                    'idle_timeout', 'idle_age', 'hard_age',
                    'actions', 'metadata'}
    LPM_FIELDS = {"nw_src", "nw_dst", "arp_spa", "arp_dpa",
                  "ipv6_dst", "ipv6_src", "dl_dst", "dl_src"}
    table_keys = collect_table_keys(rules, IGNORED_KEYS)
    print("Table keys:")
    pprint(table_keys)
    print("Rules for table:")
    pprint(collect_table_sizes(rules))
    print("LPM groups per table per field")
    pprint(collect_table_lpm(rules, LPM_FIELDS))
    print("Unique rules for table:")
    uniq_vals = collect_tale_uniq_rules(rules, IGNORED_KEYS)
    pprint({ k : len(v) for k, v in uniq_vals.items()})

