#!/usr/bin/env python3
"""clagentic-lite finding pipeline: the stable entrypoint.

Every caller (scripts/gates.sh, scripts/review-merge.sh, scripts/platform.sh,
scripts/llm-client.sh, the Reviewer and Auditor agents, `clagentic-lite gates
evaluate` and `gates profile`) runs this file by path. The logic lives in the
clagentic_findings package next to it; `findings.py --help` lists the stages
and the exit-status contract (0 ok, 1 refused or failed closed, 2 unreadable
or refused input, 70 an internal crash).

TRUST RULE. The pipeline decides whether a gate passes, and the directory it
is run from is the repository under review. The package is therefore loaded
only from this file's own resolved directory, by an explicit loader that never
consults sys.path for it, and sys.path is first stripped of the entries an
untrusted checkout can influence: the empty entry (the working directory) and
every PYTHONPATH entry. A clagentic_findings directory or module planted in the
working directory, or reachable through PYTHONPATH, is never imported.
"""
import os
import sys

PACKAGE = "clagentic_findings"
CRASH_STATUS = 70


def _drop_untrusted_path_entries():
    """Remove what the caller's working directory or environment put on
    sys.path. The interpreter's own entries (the standard library) stay."""
    from_env = set()
    for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if entry:
            from_env.add(os.path.realpath(entry))
    sys.path[:] = [entry for entry in sys.path
                   if entry != "" and os.path.realpath(entry) not in from_env]


def _load_package(directory):
    """Register the package found in DIRECTORY/clagentic_findings under its
    own name, so its relative imports resolve inside that directory alone, and
    refuse a copy that lacks any module its manifest lists. Returns the
    package's cli module."""
    # Imported here, after the path has been cleaned, so that a planted module
    # shadowing a standard-library one cannot run even for these imports.
    import importlib
    import importlib.util

    package_dir = os.path.join(directory, PACKAGE)
    spec = importlib.util.spec_from_file_location(
        PACKAGE, os.path.join(package_dir, "__init__.py"),
        submodule_search_locations=[package_dir])
    if spec is None or spec.loader is None:
        raise ImportError("no package at %s" % package_dir)
    for name in [name for name in sys.modules if name == PACKAGE or name.startswith(PACKAGE + ".")]:
        del sys.modules[name]
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    missing = [name for name in module.MODULES
               if not os.path.isfile(os.path.join(package_dir, name + ".py"))]
    if missing:
        raise ImportError("the package is incomplete, missing: %s" % ", ".join(missing))
    return importlib.import_module(PACKAGE + ".cli")


def _crash(message):
    sys.stderr.write("[clagentic-lite] %s Failing closed.\n" % message)
    return CRASH_STATUS


def main():
    directory = os.path.dirname(os.path.realpath(__file__))
    _drop_untrusted_path_entries()
    # Exception, not BaseException: SystemExit from the cli passes through unchanged.
    try:
        cli = _load_package(directory)
    except Exception as exc:  # any load failure of a damaged package must exit 70, not 1
        return _crash("the finding pipeline package in %s cannot be loaded (%s: %s); the "
                      "install is incomplete or damaged: reinstall (clagentic-lite update)."
                      % (os.path.join(directory, PACKAGE), type(exc).__name__, exc))
    try:
        return cli.run()
    except Exception as exc:  # python's default status 1 would read as a refusal to callers
        return _crash("the finding pipeline crashed (%s: %s)." % (type(exc).__name__, exc))


if __name__ == "__main__":
    sys.exit(main())
