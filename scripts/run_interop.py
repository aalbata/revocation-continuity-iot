"""Run the interoperability fixtures through both verification stacks.

Writes the fixtures to fixtures/ and the agreement table to results/interop.json.
Usage: python scripts/run_interop.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rcbench import fixtures, vc  # noqa: E402
from rcbench.world import _kill, start_node_verifier  # noqa: E402

PORT = 20930


def main() -> None:
    process = start_node_verifier(PORT, os.path.join(tempfile.gettempdir(), "rcbench-node-interop.log"))
    try:
        node = vc.NodeVerifier(PORT)
        items = fixtures.build(node)
        fixtures.save(items, os.path.join(ROOT, "fixtures"))
        table = fixtures.compare(items, vc.PythonVerifier(), node)
    finally:
        _kill(process)
    with open(os.path.join(ROOT, "results", "interop.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(table, handle, indent=1)
        handle.write("\n")
    print(f"{table['agree']} of {table['fixtures']} fixtures agree; "
          f"as expected: python {table['python_as_expected']}, node {table['node_as_expected']}")
    for row in table["rows"]:
        if not (row["agree"] and row["python_as_expected"]):
            print(" ", row["name"], "| expect", row["expect"], "| python", row["python"], "| node", row["node"])


if __name__ == "__main__":
    main()
