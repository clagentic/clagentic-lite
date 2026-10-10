"""
One module object per shared test-support module, however it is imported.

The suite imports its fixtures two ways: bare (`from isolated_env import ...`,
after a sys.path insert) and package-qualified (`from scripts.isolated_env
import ...`). Python treats those as two modules, so every module-level cache
(isolated_env's shared clone, test_support's TOOL_HOME) would exist twice in one
test process and the second copy would build its own throwaway clone.
register() makes both spellings resolve to the first-loaded object.
"""
import sys

PACKAGE = "scripts"


def register(module_name, module):
    bare = module_name.rpartition(".")[2]
    for spelling in (bare, "%s.%s" % (PACKAGE, bare)):
        sys.modules.setdefault(spelling, module)
