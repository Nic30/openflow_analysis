import os
from fnmatch import fnmatch
import json
import re

table_template = """\
\\begin{center}
\\begin{tabular}{ |c|c|c|c|c| }
\\hline
    \\textbf{Ruleset name} & \\textbf{Rules cnt.} & \\textbf{Max. unique rules per table} & \\textbf{Fields matched} & \\textbf{Field with max LPM groups} \\\\ \\hline
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


def load_ruleset_params(root):
    for fn in find_files(root, "*.json"):
        name = fn.split("/")[-2]
        with open(fn) as f:
            j = json.load(f)
            sizes = j['sizes']
            total_rule_cnt = sizes['size']
            max_rules_per_table = max([table_size for (table_size, _) in sizes["table_sizes"].values()])
            used_keys = set()
            for keys in j['table_keys'].values():
                used_keys.update(keys)
            max_lpm_field = None
            for lpms in j['table_lpm'].values():
                for field_name, lpm_groups in lpms.items():
                    if max_lpm_field is None or len(max_lpm_field[1]) < len(lpm_groups):
                        max_lpm_field = (field_name, lpm_groups)

            yield (name, total_rule_cnt, max_rules_per_table, len(used_keys),
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
    for (name, total_rule_cnt, max_rules_per_table,
         used_keys_cnt, max_lpm, max_lpm_field) in records:
        _max_lpm_field = re.search("'([0-9a-zA-Z_]+)'", max_lpm_field)
        max_lpm_field = _max_lpm_field.group(1)
        max_lpm_field = max_lpm_field.replace("_", "\_")
        name = name.replace("_", "\_")
        line = f"   \\texttt{{{name}}}\t& {total_rule_cnt}\t& {max_rules_per_table}\t& {used_keys_cnt}\t& \\texttt{{{max_lpm_field}}}: {max_lpm}\t\\\\ \\hline\n"
        line_buff.append(line)

    return table_template % "".join(line_buff)


if __name__ == "__main__":
    t = format_data_to_table(ROOT)
    print(t)
