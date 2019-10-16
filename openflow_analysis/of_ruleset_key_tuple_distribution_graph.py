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


if __name__ == "__main__":
    tuples_per_table_distribution(ROOT, "reports/tuples_per_table_distribution.png")
