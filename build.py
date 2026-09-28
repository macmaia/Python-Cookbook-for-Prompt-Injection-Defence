"""Builds each chapter as an executed notebook: every code cell runs in order in one
namespace and its printed output is stored with it, so the book never shows output
the code doesn't produce. Usage: python build.py ch01.py ch02.py ..."""
import contextlib, io, json, sys, traceback
# Uses the catraca installed in this environment (pip install catraca).


def build(spec):
    cells = []
    env = {"md": lambda s: cells.append(("markdown", s.strip("\n"))),
           "code": lambda s: cells.append(("code", s.strip("\n")))}
    exec(open(spec, encoding="utf-8").read(), env)
    ns = {"__name__": "__main__"}
    nb_cells = []
    for kind, src in cells:
        if kind == "markdown":
            nb_cells.append({"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)})
            continue
        outputs = []
        if not src.startswith("%pip"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    exec(compile(src, "<cell>", "exec"), ns)
                except Exception:
                    print(traceback.format_exc(limit=0).strip())
            if buf.getvalue():
                outputs = [{"name": "stdout", "output_type": "stream", "text": buf.getvalue().splitlines(keepends=True)}]
        nb_cells.append({"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": outputs,
                         "source": src.splitlines(keepends=True)})
    nb = {"cells": nb_cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python",
          "name": "python3"}, "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
    with open(env["OUT"], "w", encoding="utf-8") as fh:
        json.dump(nb, fh, ensure_ascii=False, indent=1)
    prose = "".join("".join(c["source"]) for c in nb_cells if c["cell_type"] == "markdown")
    dash = chr(0x2014) in prose
    print(f"== {env['OUT']}  em-dash={dash}  semicolon={';' in prose}")
    for c in nb_cells:
        if c["cell_type"] == "code" and c["outputs"]:
            print("".join(c["outputs"][0]["text"]).rstrip())
            print("-----")


for spec in sys.argv[1:]:
    build(spec)
