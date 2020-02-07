import os
from fnmatch import fnmatch
import json
import re
import matplotlib.pyplot as plt
from openflow_analysis.of_ruleset_feature_table_gen import find_files
from docutils.languages import da
from matplotlib import ticker

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


def load_ruleset_params(root):
    table_tuple_cnt = {}
    for fn in find_files(root, "*.json"):
        with open(fn) as f:
            j = json.load(f)
            for tuples_per_table in j["table_key_tuples"].values():
                tuple_cnt = len(tuples_per_table)
                t_cnt = table_tuple_cnt.get(tuple_cnt, 0)
                table_tuple_cnt[tuple_cnt] = t_cnt + 1
    return table_tuple_cnt


def tuples_per_table_distribution(root, graph_file):
    # { tuples_cnt: table with such a number cnt }
    records = load_ruleset_params(root)
    data = []
    for k, v in records.items():
        for _ in range(v):
            data.append(k)

    fig, ax = plt.subplots()
    num_bins = 20
    ax.hist(data, num_bins, facecolor='blue', alpha=0.5)
    ax.yaxis.set_major_formatter(ticker.PercentFormatter(xmax=len(data)))

    ax.set_ylabel('% of tables')
    ax.set_xlabel('Number of tuples per table')
    # ax.set_xlim(left=0)

    plt.grid()
    plt.savefig(graph_file)


def load_table_size_X_tuples(file_name):
    table_tuple_cnt = {}
    table_rule_cnt = {}
    with open(file_name) as f:
        j = json.load(f)
        for table_i, tuples_per_table in j["table_key_tuples"].items():
            assert table_i not in table_tuple_cnt.keys()
            table_tuple_cnt[table_i] = len(tuples_per_table)
            size = 0
            for rec in tuples_per_table.values():
                (used, _, _) = eval(rec)
                size += used
            table_rule_cnt[table_i] = table_rule_cnt.get(table_i, 0) + size
    data = []
    for table_i, tuple_cnt in table_tuple_cnt.items():
        rule_cnt = table_rule_cnt[table_i]
        data.append((table_i, tuple_cnt, rule_cnt))
    print(data)
    return data


def _tuples_rules_per_table(report_file, graph_file):
    # { tuples_cnt: table with such a number cnt }
    records = load_table_size_X_tuples(report_file)
    tables = [d[0] for d in records]
    tuple_cnt = [d[1] for d in records]
    rule_cnt = [d[2] for d in records]

    fig, ax0 = plt.subplots(figsize=(12, 4))
    ax0.set_xlabel('Table id')

    ax0.plot(tables, tuple_cnt, 'x', color="blue")
    ax0.set_ylabel('Number of key tuples', color="blue")

    ax1 = ax0.twinx()  # instantiate a second axes that shares the same x-axis
    ax1.set_yscale('log')
    ax1.set_ylabel('Number of rules', color="red")
    ax1.plot(tables, rule_cnt, 'x', color="red")

    for x in tables:
        plt.axvline(x=x, linestyle=":", color="gray")

    plt.grid()
    plt.savefig(graph_file)


def tuples_rules_per_table(ruleset):
    _tuples_rules_per_table(os.path.join(ROOT, f"{ruleset}/report.json"),
                           f"reports/fig/{ruleset}-tuples_per_table_distribution.png")


if __name__ == "__main__":
    tuples_per_table_distribution(ROOT, "reports/tuples_per_table_distribution.png")
