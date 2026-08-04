"""
Regression tests for bin/clagentic-lite symlink self-locate resolution
(lr-121496 / GH #135).

Root cause: the bootstrap fallback in bin/clagentic-lite (the block that runs
before scripts/platform.sh is sourced, used when $CLAGENTIC_LITE_HOME is unset
or stale) took `dirname "$0"` directly to derive _SELF_DIR. `dirname` does not
resolve symlinks. Normal invocation is via the init-created symlink at
~/.local/bin/clagentic-lite -> <checkout>/bin/clagentic-lite, so $0 is the
symlink path and _SELF_DIR/_SELF_SCRIPTS resolved against ~/.local/bin
instead of the checkout, producing:
  "clagentic-lite: cannot find scripts/platform.sh in <bad path>"

The fix resolves $0 through symlinks (readlink -f, with a python3 and manual
readlink-loop fallback for portability -- no GNU-only readlink -f assumption)
before taking dirname.

These tests invoke the ACTUAL bin/clagentic-lite script via subprocess,
through a real symlink on disk, exactly as the ~/.local/bin install does --
a Python reimplementation of the resolution logic would not catch a
regression in the real shell code.

Run with: python3 -m unittest scripts/test_bin_clagentic_lite_symlink_self_locate.py -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _make_fake_checkout(root):
    """Build a minimal-but-real clagentic-lite checkout under `root`:
    bin/clagentic-lite (the real script, copied byte-for-byte) plus the real
    scripts/ directory it needs to find (platform.sh, gates.sh) so the
    bootstrap "does this look like a checkout" check passes.
    """
    bin_dir = os.path.join(root, "bin")
    scripts_dir = os.path.join(root, "scripts")
    os.makedirs(bin_dir)
    os.makedirs(scripts_dir)

    dest_cli = os.path.join(bin_dir, "clagentic-lite")
    shutil.copyfile(CLI, dest_cli)
    os.chmod(dest_cli, 0o755)

    for name in ("platform.sh", "gates.sh"):
        src = os.path.join(TOOL_HOME, "scripts", name)
        shutil.copyfile(src, os.path.join(scripts_dir, name))

    return dest_cli


def _run_cli(argv, cwd, env_extra=None):
    env = dict(os.environ)
    # Force the "unset CLAGENTIC_LITE_HOME, install moved off the compiled-in
    # default" bootstrap fallback path under test -- this is the exact
    # reporter scenario (legacy checkout path, var unset).
    env.pop("CLAGENTIC_LITE_HOME", None)
    env.pop("CLAGENTIC_HOME", None)
    env["HOME"] = cwd
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestSymlinkedSelfLocate(unittest.TestCase):
    """Invocation through ~/.local/bin/clagentic-lite -> <checkout>/bin/clagentic-lite,
    CLAGENTIC_LITE_HOME unset, mirrors the exact GH #135 repro."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-symlink-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        # Checkout lives somewhere NOT matching the compiled-in default
        # ($HOME/.clagentic/lite) -- e.g. the legacy ~/.clagentic-lite path
        # the reporter was on, unrelated to $HOME here entirely, to prove
        # resolution comes from the symlink target, not the default guess.
        self.checkout = os.path.join(self.tmpdir, "checkout")
        os.makedirs(self.checkout)
        self.real_cli = _make_fake_checkout(self.checkout)

        # ~/.local/bin/clagentic-lite -> checkout/bin/clagentic-lite, exactly
        # as _install_symlink() creates it during `clagentic-lite init`.
        local_bin = os.path.join(self.tmpdir, ".local", "bin")
        os.makedirs(local_bin)
        self.symlink = os.path.join(local_bin, "clagentic-lite")
        os.symlink(self.real_cli, self.symlink)

    def test_list_via_symlink_resolves_scripts_dir(self):
        """`list` (no registry yet) must not hit the bootstrap
        "cannot find scripts/platform.sh" failure when invoked via the
        symlink with CLAGENTIC_LITE_HOME unset."""
        rc, out, err = _run_cli([self.symlink, "list"], cwd=self.tmpdir)
        self.assertNotIn("cannot find scripts/platform.sh", err, msg=err)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

    def test_doctor_via_symlink_reports_correct_home(self):
        """doctor's first check line names CLAGENTIC_LITE_HOME -- assert it
        realigned to the checkout (the symlink target's parent), not the
        symlink's own directory (~/.local/bin) or the compiled-in default."""
        rc, out, err = _run_cli(
            [self.symlink, "doctor"],
            cwd=self.tmpdir,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertNotIn("cannot find scripts/platform.sh", err, msg=err)
        self.assertIn(f"CLAGENTIC_LITE_HOME={self.checkout}", out, msg=out)

    def test_direct_invocation_still_works_no_symlink(self):
        """Control case: invoking bin/clagentic-lite directly (no symlink)
        must keep working post-fix -- the fix must not regress the plain
        dirname($0) path when $0 is not a symlink."""
        rc, out, err = _run_cli([self.real_cli, "list"], cwd=self.tmpdir)
        self.assertNotIn("cannot find scripts/platform.sh", err, msg=err)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

    def test_failure_message_names_resolution_attempts(self):
        """When resolution genuinely fails (scripts/platform.sh missing from
        the checkout the symlink resolves to), the error must name the
        attempts made -- $0, the resolved self path, and the directory
        checked -- not just the default home, per the hard requirement in
        lr-121496. The symlink itself must stay resolvable (only the target
        file inside the checkout is removed) so exec still reaches the real
        script and exercises its own failure-message code path."""
        os.remove(os.path.join(self.checkout, "scripts", "platform.sh"))

        rc, out, err = _run_cli([self.symlink, "list"], cwd=self.tmpdir)
        self.assertNotEqual(rc, 0)
        self.assertIn("cannot find scripts/platform.sh", err)
        self.assertIn("invoked as ($0)", err, msg=err)
        self.assertIn("resolved self path", err, msg=err)


class TestPortableSelfLocateNoGnuReadlinkF(unittest.TestCase):
    """Prove resolution does not hard-depend on GNU readlink -f: with a fake
    `readlink` on PATH that only supports the POSIX single-hop form (no -f
    flag, mirrors legacy BSD readlink), self-locate through the symlink must
    still succeed via the python3 or manual-hop fallback."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-noreadlinkf-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        self.checkout = os.path.join(self.tmpdir, "checkout")
        os.makedirs(self.checkout)
        self.real_cli = _make_fake_checkout(self.checkout)

        local_bin = os.path.join(self.tmpdir, ".local", "bin")
        os.makedirs(local_bin)
        self.symlink = os.path.join(local_bin, "clagentic-lite")
        os.symlink(self.real_cli, self.symlink)

        # Fake `readlink` on PATH ahead of the real one: exits nonzero on -f
        # (simulating a readlink build with no -f support), falls back to the
        # real system readlink for the plain single-arg form so the manual
        # hop loop in _bootstrap_resolve_self can still make progress.
        fakebin = os.path.join(self.tmpdir, "fakebin")
        os.makedirs(fakebin)
        real_readlink = shutil.which("readlink") or "/usr/bin/readlink"
        fake_readlink = os.path.join(fakebin, "readlink")
        with open(fake_readlink, "w") as f:
            f.write(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  -f) exit 1 ;;\n"
                "esac\n"
                f"exec {real_readlink} \"$@\"\n"
            )
        os.chmod(fake_readlink, 0o755)
        self.fakebin = fakebin

    def test_resolves_without_readlink_dash_f(self):
        env = dict(os.environ)
        env.pop("CLAGENTIC_LITE_HOME", None)
        env.pop("CLAGENTIC_HOME", None)
        env["HOME"] = self.tmpdir
        env["PATH"] = self.fakebin + os.pathsep + env.get("PATH", "")

        proc = subprocess.run(
            [self.symlink, "list"],
            cwd=self.tmpdir,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotIn("cannot find scripts/platform.sh", proc.stderr, msg=proc.stderr)
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout!r} stderr={proc.stderr!r}")


if __name__ == "__main__":
    unittest.main()
