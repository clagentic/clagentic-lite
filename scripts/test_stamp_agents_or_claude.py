"""
The enrollment stamp (managed-by marker) lives in AGENTS.md or CLAUDE.md, at
the repo level or the wrapper level, and update/doctor report on it
accordingly.

Covered defects:
  D1  update warned about (and, on a tty, prompted for) the nested repo's own
      project-owned CLAUDE.md in the wrapper layout.
  D2  the warning advised `update --restamp`, which cannot add a notice.
  D3  doctor warned about a nested repo's CLAUDE.md in the wrapper layout.
  D4  update/restamp located the wrapper with dirname, missing wrapper/group/repo.
  D5  every stamp check and write was CLAUDE.md-only.

Every scenario runs against a throwaway clone of the tool and scratch repos
under a temp HOME; nothing touches the live checkout.

Run with: python3 -m unittest scripts.test_stamp_agents_or_claude -v
"""
import os
import shutil
import subprocess

from scripts.test_enroll_tracked_file_writes import _Base, _init_repo, _read, _write

MARKER = b"managed-by: clagentic"
UPDATE_ENV = {"CLAGENTIC_SKIP_FETCH": "1"}
PROJECT_OWNED = b"# Project rules\n\nDo not touch.\n"


class _StampBase(_Base):
    def setUp(self):
        super().setUp()
        # The overlaid scratch clone is dirty against its own HEAD, and update's
        # non-tty discard path would revert it to committed (old) code before
        # restamping. Commit the overlay in the disposable clone so update runs
        # the code under test and needs no discard opt-in.
        subprocess.run(["git", "-C", self.tool_home, "commit", "-qa", "--allow-empty",
                        "-m", "overlay"], check=True, capture_output=True)

    def notice_template(self, name="CLAUDE.md"):
        path = os.path.join(self.tool_home, "share", "hook-shims", "CLAUDE.md.template")
        text = _read(path)
        return text.replace(b"# CLAUDE.md\n", b"# " + name.encode() + b"\n", 1)

    def update(self, cwd, *flags):
        return self.run_cli(["update"] + list(flags), cwd=cwd, **UPDATE_ENV)

    def enroll_wrapper(self, wrapper):
        # "A" answers the multi-repo prompt; a single nested repo takes the default.
        rc, out, err = self.run_cli_tty(["enroll", wrapper], cwd=wrapper, answer=b"A\n")
        self.assertEqual(rc, 0, out + err)

    def lines_about(self, text, path):
        return [l for l in text.splitlines() if path in l]

    def _find_stub(self, order):
        real = shutil.which("find")
        stub_dir = os.path.join(self.tmpdir, "stub-" + order)
        os.makedirs(stub_dir)
        script = os.path.join(stub_dir, "find")
        # Reorders only the nested-repo scan; every other find passes through.
        _write(script, ("#!/bin/sh\n"
                        "case \"$*\" in\n"
                        "  *\"-name .git\"*) %s \"$@\" | sort %s ;;\n"
                        "  *) exec %s \"$@\" ;;\n"
                        "esac\n" % (real, "-r" if order == "reverse" else "", real)).encode())
        os.chmod(script, 0o755)
        return stub_dir


class TestWrapperNestedFilesAreProjectOwned(_StampBase):
    def _check(self, filename, repo_rel):
        wrapper = os.path.join(self.tmpdir, "wrapper-" + filename)
        nested = os.path.join(wrapper, repo_rel)
        os.makedirs(wrapper)
        _init_repo(nested)
        owned = os.path.join(nested, filename)
        _write(owned, PROJECT_OWNED)
        self.enroll_wrapper(wrapper)
        self.assertEqual(_read(owned), PROJECT_OWNED)

        rc, out, err = self.update(nested)
        self.assertEqual(rc, 0, out + err)
        # update may print either spelling of the path; match both so the loop
        # cannot pass vacuously on a realpath/tmp mismatch.
        for line in self.lines_about(out + err, nested) + self.lines_about(
                out + err, os.path.realpath(nested)):
            self.assertNotIn("notice", line.lower(), line)
            self.assertNotIn("--restamp", line, line)
        self.assertNotIn("enrollment notice", out + err)
        self.assertEqual(_read(owned), PROJECT_OWNED)

        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(owned), PROJECT_OWNED)

        # The registry holds canonical paths, so match on the resolved one; an
        # empty match would make the checks below pass vacuously.
        canonical = os.path.realpath(nested)
        _rc, out, err = self.run_doctor(self.tmpdir, canonical)
        nested_lines = self.lines_about(out, canonical)
        self.assertTrue(nested_lines, out)
        for line in nested_lines:
            if filename in line or "notice" in line.lower():
                self.assertNotIn("WARN", line, line)
        owned_ok = [l for l in nested_lines if "project-owned" in l]
        self.assertEqual(len(owned_ok), 1, out)
        self.assertNotIn("no CLAUDE.md by design", owned_ok[0])

        # tty update: no prompt about the nested repo's own file.
        rc, out, err = self.run_cli_tty(["update"], cwd=nested, answer=b"n\n", **UPDATE_ENV)
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("Re-add the enrollment notice", out + err)
        self.assertNotIn("enrollment notice", out + err)
        self.assertEqual(_read(owned), PROJECT_OWNED)

    def test_claude_md(self):
        self._check("CLAUDE.md", "proj")

    def test_agents_md(self):
        self._check("AGENTS.md", "proj")

    def test_claude_md_two_levels_deep(self):
        self._check("CLAUDE.md", os.path.join("group", "proj"))


class TestWrapperStampInAgentsMd(_StampBase):
    def setUp(self):
        super().setUp()
        self.wrapper = os.path.join(self.tmpdir, "wrapper")
        self.nested = os.path.join(self.wrapper, "proj")
        os.makedirs(self.wrapper)
        _init_repo(self.nested)
        self.enroll_wrapper(self.wrapper)
        # Move the wrapper stamp into AGENTS.md: the stamp now lives only there.
        cm = os.path.join(self.wrapper, "CLAUDE.md")
        self.agents = os.path.join(self.wrapper, "AGENTS.md")
        body = _read(cm).replace(b"clagentic-wrapper-version: v2", b"clagentic-wrapper-version: v1")
        _write(self.agents, body)
        os.remove(cm)

    def test_doctor_and_update_treat_it_as_stamped_without_creating_claude_md(self):
        _rc, out, _err = self.run_doctor(self.tmpdir, self.nested)
        self.assertIn("AGENTS.md carries the enrollment stamp", out)

        rc, out, err = self.update(self.nested)
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(os.path.join(self.wrapper, "CLAUDE.md")))
        restamped = _read(self.agents)
        self.assertIn(b"clagentic-wrapper-version: v2", restamped)
        self.assertEqual(restamped.count(MARKER), 1)

    def test_doctor_reports_each_wrapper_once_despite_several_repos(self):
        _init_repo(os.path.join(self.wrapper, "other"))
        self.enroll_wrapper(self.wrapper)
        _write(os.path.join(self.wrapper, "CLAUDE.md"), PROJECT_OWNED)
        _rc, out, _err = self.run_doctor(self.tmpdir, self.nested)
        stamp_ok = [l for l in out.splitlines() if "carries the enrollment stamp" in l]
        self.assertEqual(len(stamp_ok), 1, out)
        info = [l for l in out.splitlines() if "does not load AGENTS.md by default" in l]
        self.assertEqual(len(info), 1, out)
        checking = [l for l in out.splitlines() if l.strip().startswith("checking ")]
        self.assertEqual(len(checking), 1, out)

    def test_enroll_does_not_add_a_second_stamp(self):
        _init_repo(os.path.join(self.wrapper, "other"))
        self.enroll_wrapper(self.wrapper)
        self.assertFalse(os.path.exists(os.path.join(self.wrapper, "CLAUDE.md")))


class TestWrapperTwoLevelsDeepRestamp(_StampBase):
    def test_update_finds_the_wrapper(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "group", "proj")
        os.makedirs(wrapper)
        _init_repo(nested)
        self.enroll_wrapper(wrapper)
        cm = os.path.join(wrapper, "CLAUDE.md")
        _write(cm, _read(cm).replace(b"clagentic-wrapper-version: v2", b"clagentic-wrapper-version: v1"))

        rc, out, err = self.update(nested)
        self.assertEqual(rc, 0, out + err)
        self.assertIn(b"clagentic-wrapper-version: v2", _read(cm))


class TestRegularRepoStampedInAgentsMd(_StampBase):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_repo(self.repo)
        self.agents = os.path.join(self.repo, "AGENTS.md")
        stale = self.notice_template("AGENTS.md").replace(
            b"clagentic-notice-version: v2", b"clagentic-notice-version: v1")
        _write(self.agents, stale + b"\nproject-owned line\n")

    def test_enroll_refreshes_agents_md_and_creates_no_claude_md(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "CLAUDE.md")))
        body = _read(self.agents)
        self.assertIn(b"clagentic-notice-version: v2", body)
        self.assertIn(b"project-owned line", body)
        self.assertTrue(body.startswith(b"# AGENTS.md\n"))
        self.assertEqual(body.count(MARKER), 1)

    def test_doctor_ok_and_update_restamps_only_agents_md(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        _write(self.agents, _read(self.agents).replace(
            b"clagentic-notice-version: v2", b"clagentic-notice-version: v1"))
        canonical = os.path.realpath(self.repo)
        _rc, out, _err = self.run_doctor(self.tmpdir, canonical)
        notice_lines = [l for l in self.lines_about(out, canonical) if "notice" in l]
        self.assertTrue(notice_lines, out)
        for line in notice_lines:
            self.assertNotIn("WARN", line, line)

        rc, out, err = self.update(self.repo)
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "CLAUDE.md")))
        body = _read(self.agents)
        self.assertIn(b"clagentic-notice-version: v2", body)
        self.assertIn(b"project-owned line", body)
        self.assertEqual(body.count(MARKER), 1)

    def test_info_when_claude_md_exists_beside_agents_md_stamp(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        claude = os.path.join(self.repo, "CLAUDE.md")
        _write(claude, PROJECT_OWNED)
        _rc, out, _err = self.run_doctor(self.tmpdir, self.repo)
        info = [l for l in out.splitlines() if "does not load AGENTS.md by default" in l]
        self.assertEqual(len(info), 1, out)
        self.assertTrue(info[0].lstrip().startswith("INFO"), info[0])
        self.assertEqual(_read(claude), PROJECT_OWNED)
        rc, out, err = self.update(self.repo)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(claude), PROJECT_OWNED)
        self.assertNotIn("enrollment notice", out + err)


class TestUnmanagedFilesNeverOverwritten(_StampBase):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_repo(self.repo)

    def _every_command(self):
        for argv, extra in (
            (["enroll", self.repo], {}),
            (["enroll", "--force", self.repo], {}),
            (["update"], UPDATE_ENV),
            (["update", "--restamp"], UPDATE_ENV),
        ):
            rc, out, err = self.run_cli(argv, cwd=self.repo, **extra)
            self.assertEqual(rc, 0, " ".join(argv) + "\n" + out + err)

    def test_unmanaged_claude_md(self):
        path = os.path.join(self.repo, "CLAUDE.md")
        _write(path, PROJECT_OWNED)
        self._every_command()
        self.assertEqual(_read(path), PROJECT_OWNED)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "AGENTS.md")))

    def test_unmanaged_agents_md_gets_an_importing_claude_md(self):
        agents = os.path.join(self.repo, "AGENTS.md")
        _write(agents, PROJECT_OWNED)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        claude = _read(os.path.join(self.repo, "CLAUDE.md"))
        self.assertIn(MARKER, claude)
        self.assertEqual(claude.count(b"@AGENTS.md"), 1)
        self.assertTrue(claude.endswith(b"<!-- /clagentic-notice -->\n\n@AGENTS.md\n"), claude)
        self._every_command()
        self.assertEqual(_read(agents), PROJECT_OWNED)
        # Restamp keeps the import exactly once, after a stale-version restamp.
        claude_path = os.path.join(self.repo, "CLAUDE.md")
        _write(claude_path, _read(claude_path).replace(
            b"clagentic-notice-version: v2", b"clagentic-notice-version: v1"))
        rc, out, err = self.update(self.repo, "--restamp")
        self.assertEqual(rc, 0, out + err)
        after = _read(claude_path)
        self.assertIn(b"clagentic-notice-version: v2", after)
        self.assertEqual(after.count(b"@AGENTS.md"), 1)
        self.assertEqual(_read(agents), PROJECT_OWNED)
        self.assertNotIn(MARKER, _read(agents))

    def test_update_warning_for_unmanaged_claude_md_names_enroll_not_restamp(self):
        _write(os.path.join(self.repo, "CLAUDE.md"), PROJECT_OWNED)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        rc, out, err = self.update(self.repo)
        self.assertEqual(rc, 0, out + err)
        warned = [l for l in (out + err).splitlines() if "no enrollment notice" in l]
        self.assertEqual(len(warned), 1, out + err)
        self.assertNotIn("--restamp", warned[0])
        self.assertIn("enroll", warned[0])
        self.assertIn("CLAUDE.md", warned[0])

    def test_doctor_names_what_enroll_will_write(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        os.remove(os.path.join(self.repo, "CLAUDE.md"))
        canonical = os.path.realpath(self.repo)
        _rc, out, _err = self.run_doctor(self.tmpdir, canonical)
        lines = [l for l in self.lines_about(out, canonical) if "no enrollment notice" in l]
        self.assertEqual(len(lines), 1, out)
        self.assertIn("writes CLAUDE.md", lines[0])


class TestWrapperUnmanagedAgentsMd(_StampBase):
    def test_wrapper_claude_md_imports_agents_md_and_leaves_it_alone(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "proj")
        os.makedirs(wrapper)
        _init_repo(nested)
        agents = os.path.join(wrapper, "AGENTS.md")
        _write(agents, PROJECT_OWNED)
        self.enroll_wrapper(wrapper)
        claude = os.path.join(wrapper, "CLAUDE.md")
        self.assertIn(MARKER, _read(claude))
        self.assertEqual(_read(claude).count(b"@AGENTS.md"), 1)
        _write(claude, _read(claude).replace(
            b"clagentic-wrapper-version: v2", b"clagentic-wrapper-version: v1"))
        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        after = _read(claude)
        self.assertIn(b"clagentic-wrapper-version: v2", after)
        self.assertEqual(after.count(b"@AGENTS.md"), 1)
        self.assertEqual(_read(agents), PROJECT_OWNED)

    def _enrolled_wrapper(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "proj")
        os.makedirs(wrapper)
        _init_repo(nested)
        self.enroll_wrapper(wrapper)
        return wrapper, nested

    def test_import_added_when_agents_md_appears_later(self):
        wrapper, nested = self._enrolled_wrapper()
        claude = os.path.join(wrapper, "CLAUDE.md")
        self.assertEqual(_read(claude).count(b"@AGENTS.md"), 0)
        agents = os.path.join(wrapper, "AGENTS.md")
        _write(agents, PROJECT_OWNED)
        rc, out, err = self.update(nested)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(claude).count(b"@AGENTS.md"), 1)
        self.assertEqual(_read(agents), PROJECT_OWNED)

    def test_import_dropped_when_agents_md_is_deleted(self):
        wrapper, nested = self._enrolled_wrapper()
        claude = os.path.join(wrapper, "CLAUDE.md")
        agents = os.path.join(wrapper, "AGENTS.md")
        _write(agents, PROJECT_OWNED)
        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(claude).count(b"@AGENTS.md"), 1)
        os.remove(agents)
        rc, out, err = self.update(nested)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(claude).count(b"@AGENTS.md"), 0)

    def test_wrapper_force_never_overwrites_unmanaged_wrapper_claude_md(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        os.makedirs(wrapper)
        _init_repo(os.path.join(wrapper, "proj"))
        owned = os.path.join(wrapper, "CLAUDE.md")
        _write(owned, PROJECT_OWNED)
        rc, out, err = self.run_cli_tty(["enroll", "--force", wrapper], cwd=wrapper)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(owned), PROJECT_OWNED)


class TestWrapperImportsNestedAgentsMd(_StampBase):
    """Claude Code skips a nested AGENTS.md while an ancestor has a CLAUDE.md
    (observed on claude 2.1.284), so the managed wrapper CLAUDE.md imports it."""

    def _wrapper_with_agents_only_repo(self, repo_rel="proj"):
        self.wrapper = os.path.join(self.tmpdir, "wrapper")
        self.nested = os.path.join(self.wrapper, repo_rel)
        self.import_line = ("@%s/AGENTS.md" % repo_rel.replace(os.sep, "/")).encode()
        os.makedirs(self.wrapper)
        _init_repo(self.nested)
        self.nested_agents = os.path.join(self.nested, "AGENTS.md")
        _write(self.nested_agents, PROJECT_OWNED)
        self.enroll_wrapper(self.wrapper)
        self.wrapper_claude = os.path.join(self.wrapper, "CLAUDE.md")

    def _import_lines(self):
        return [l for l in _read(self.wrapper_claude).splitlines()
                if l.startswith(b"@") and l.endswith(b"/AGENTS.md")]

    def _assert_nested_untouched(self):
        self.assertEqual(_read(self.nested_agents), PROJECT_OWNED)
        self.assertFalse(os.path.exists(os.path.join(self.nested, "CLAUDE.md")))

    def test_import_line_after_enroll_and_idempotent_restamp(self):
        self._wrapper_with_agents_only_repo()
        self.assertEqual(self._import_lines(), [self.import_line])
        self._assert_nested_untouched()
        for _ in range(2):
            rc, out, err = self.update(self.nested, "--restamp")
            self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._import_lines(), [self.import_line])
        self._assert_nested_untouched()

    def test_two_levels_deep_uses_the_relative_path(self):
        self._wrapper_with_agents_only_repo(os.path.join("group", "proj"))
        self.assertEqual(self._import_lines(), [b"@group/proj/AGENTS.md"])
        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._import_lines(), [b"@group/proj/AGENTS.md"])

    def test_repo_gaining_a_claude_md_loses_its_line(self):
        self._wrapper_with_agents_only_repo()
        self.assertEqual(self._import_lines(), [self.import_line])
        own = os.path.join(self.nested, "CLAUDE.md")
        _write(own, PROJECT_OWNED)
        rc, out, err = self.update(self.nested)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._import_lines(), [])
        self.assertEqual(_read(own), PROJECT_OWNED)
        self.assertEqual(_read(self.nested_agents), PROJECT_OWNED)

    def test_repo_without_agents_md_gets_no_line(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        os.makedirs(wrapper)
        _init_repo(os.path.join(wrapper, "proj"))
        self.enroll_wrapper(wrapper)
        text = _read(os.path.join(wrapper, "CLAUDE.md"))
        self.assertNotIn(b"/AGENTS.md", text)

    def test_doctor_warns_until_restamp_fixes_it(self):
        self._wrapper_with_agents_only_repo()
        canonical = os.path.realpath(self.nested)
        _write(self.wrapper_claude, b"\n".join(
            l for l in _read(self.wrapper_claude).splitlines() if l != self.import_line) + b"\n")

        _rc, out, _err = self.run_doctor(self.tmpdir, canonical)
        warns = [l for l in self.lines_about(out, canonical) if "not imported" in l]
        self.assertEqual(len(warns), 1, out)
        self.assertIn("WARN", warns[0])
        self.assertIn("update --restamp", warns[0])

        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        _rc, out, _err = self.run_doctor(self.tmpdir, canonical)
        self.assertTrue(self.lines_about(out, canonical), out)
        self.assertEqual([l for l in out.splitlines() if "not imported" in l], [], out)
        self._assert_nested_untouched()

    def test_plain_update_repairs_a_missing_line(self):
        self._wrapper_with_agents_only_repo()
        _write(self.wrapper_claude, b"\n".join(
            l for l in _read(self.wrapper_claude).splitlines() if l != self.import_line) + b"\n")
        rc, out, err = self.update(self.nested)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._import_lines(), [self.import_line])

    def test_unmanaged_wrapper_claude_md_is_never_edited_or_warned_about(self):
        self._wrapper_with_agents_only_repo()
        _write(self.wrapper_claude, PROJECT_OWNED)
        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(self.wrapper_claude), PROJECT_OWNED)
        canonical = os.path.realpath(self.nested)
        _rc, out, _err = self.run_doctor(self.tmpdir, canonical)
        self.assertTrue(self.lines_about(out, canonical), out)
        self.assertNotIn("not imported", out)


class TestRepoLevelAgentsImportTracksAgentsMd(_StampBase):
    """The repo-level @AGENTS.md import is regenerated like the wrapper's: it
    appears when AGENTS.md is added later and goes when AGENTS.md is deleted."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_repo(self.repo)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        self.claude = os.path.join(self.repo, "CLAUDE.md")
        self.agents = os.path.join(self.repo, "AGENTS.md")

    def _imports(self):
        return _read(self.claude).count(b"@AGENTS.md")

    def test_import_added_when_agents_md_appears_later(self):
        self.assertEqual(self._imports(), 0)
        _write(self.agents, PROJECT_OWNED)
        rc, out, err = self.update(self.repo)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._imports(), 1)
        self.assertEqual(_read(self.agents), PROJECT_OWNED)
        rc, out, err = self.update(self.repo, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._imports(), 1)

    def test_import_dropped_when_agents_md_is_deleted(self):
        _write(self.agents, PROJECT_OWNED)
        rc, out, err = self.update(self.repo, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._imports(), 1)
        os.remove(self.agents)
        rc, out, err = self.update(self.repo)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._imports(), 0)
        self.assertIn(MARKER, _read(self.claude))

    def test_enroll_regenerates_the_import(self):
        _write(self.agents, PROJECT_OWNED)
        rc, _o, err = self.run_cli(["enroll", "--force", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._imports(), 1)
        os.remove(self.agents)
        rc, _o, err = self.run_cli(["enroll", "--force", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._imports(), 0)


ABOVE = b"# Team notes\n\nwritten above the stamp\n\n"
BELOW = b"\n## Local notes\n\nwritten below the stamp\n"


class TestWrapperRestampKeepsProjectContent(_StampBase):
    """Only the generated region of a managed wrapper file is rewritten; content
    above or below it survives every command that restamps, and the generated
    import lines are replaced rather than duplicated."""

    def _wrapper(self, stamp_file):
        self.wrapper = os.path.join(self.tmpdir, "wrapper")
        self.nested = os.path.join(self.wrapper, "proj")
        os.makedirs(self.wrapper)
        _init_repo(self.nested)
        _write(os.path.join(self.nested, "AGENTS.md"), PROJECT_OWNED)
        self.enroll_wrapper(self.wrapper)
        self.stamped = os.path.join(self.wrapper, stamp_file)
        claude = os.path.join(self.wrapper, "CLAUDE.md")
        if stamp_file == "AGENTS.md":
            body = _read(claude).replace(b"# CLAUDE.md\n", b"# AGENTS.md\n", 1)
            _write(self.stamped, body)
            os.remove(claude)
        _write(self.stamped, ABOVE + _read(self.stamped) + BELOW)

    def _assert_preserved(self, step):
        body = _read(self.stamped)
        self.assertTrue(body.startswith(ABOVE), step)
        self.assertTrue(body.endswith(BELOW), step)
        self.assertEqual(body.count(MARKER), 1, step)
        self.assertEqual(body.count(b"@proj/AGENTS.md"),
                         1 if self.stamped.endswith("CLAUDE.md") else 0, step)
        self.assertEqual(body.count(b"## Enrolled projects"), 1, step)

    def _stale(self):
        _write(self.stamped, _read(self.stamped).replace(
            b"clagentic-wrapper-version: v2", b"clagentic-wrapper-version: v1"))

    def _check(self, stamp_file):
        self._wrapper(stamp_file)
        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self._assert_preserved("update --restamp")

        self._stale()
        rc, out, err = self.update(self.nested)
        self.assertEqual(rc, 0, out + err)
        self.assertIn(b"clagentic-wrapper-version: v2", _read(self.stamped))
        self._assert_preserved("update")

        rc, out, err = self.run_cli_tty(["enroll", "--force", self.wrapper], cwd=self.wrapper)
        self.assertEqual(rc, 0, out + err)
        self._assert_preserved("enroll --force")

        # A pointer change: a second repo joins the wrapper. The pointer is
        # edited directly because enrolling several repos in one prompt
        # depends on directory order.
        other = os.path.join(self.wrapper, "other")
        _init_repo(other)
        with open(os.path.join(self.wrapper, ".clagentic-project"), "a") as ptr:
            ptr.write(os.path.realpath(other) + "\n")
        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self._assert_preserved("restamp after a pointer change")
        self.assertIn(b"`other`", _read(self.stamped))
        self.assertEqual(os.path.exists(os.path.join(self.wrapper, "CLAUDE.md")),
                         stamp_file == "CLAUDE.md")

    def test_claude_md(self):
        self._check("CLAUDE.md")

    def test_agents_md(self):
        self._check("AGENTS.md")

    def test_wrapper_agents_md_gets_no_nested_imports(self):
        self._wrapper("AGENTS.md")
        rc, out, err = self.update(self.nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn(b"@proj/AGENTS.md", _read(self.stamped))
        self.assertFalse(os.path.exists(os.path.join(self.wrapper, "CLAUDE.md")))

    def test_file_with_nothing_around_the_region_is_stable(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "proj")
        os.makedirs(wrapper)
        _init_repo(nested)
        _write(os.path.join(wrapper, "AGENTS.md"), PROJECT_OWNED)
        _write(os.path.join(nested, "AGENTS.md"), PROJECT_OWNED)
        self.enroll_wrapper(wrapper)
        claude = os.path.join(wrapper, "CLAUDE.md")
        first = _read(claude)
        self.assertTrue(first.endswith(b"\n@AGENTS.md\n\n@proj/AGENTS.md\n"), first)
        # The table's status column changes once the nested hooks exist, so the
        # snapshot is taken after one restamp.
        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        settled = _read(claude)
        self.assertTrue(settled.endswith(b"\n@AGENTS.md\n\n@proj/AGENTS.md\n"), settled)
        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(claude), settled)

    def test_template_tail_still_matches_the_region_anchor(self):
        path = os.path.join(self.tool_home, "share", "hook-shims",
                            "CLAUDE.md.wrapper.template")
        lines = [l for l in _read(path).splitlines() if l.strip()]
        self.assertEqual(lines[-2:], [b"clagentic-lite show memory [N]", b"```"])


class TestHandWrittenImportsOutsideTheRegion(_StampBase):
    """Only the generated region's import lines are drift. A hand-written
    @...AGENTS.md line elsewhere in a managed wrapper CLAUDE.md is project-owned:
    it must not make every update restamp, because no restamp could clear it."""

    def test_hand_written_imports_never_trigger_a_restamp(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "proj")
        os.makedirs(wrapper)
        _init_repo(nested)
        _write(os.path.join(nested, "AGENTS.md"), PROJECT_OWNED)
        self.enroll_wrapper(wrapper)
        rc, out, err = self.update(nested, "--restamp")
        self.assertEqual(rc, 0, out + err)

        claude = os.path.join(wrapper, "CLAUDE.md")
        mine = b"\n## Mine\n\n@notes/AGENTS.md\n@AGENTS.md\n"
        _write(claude, _read(claude) + mine)
        before = _read(claude)

        for attempt in range(2):
            rc, out, err = self.update(nested)
            self.assertEqual(rc, 0, out + err)
            self.assertNotIn("stamped wrapper", out + err, "attempt %d" % attempt)
            self.assertEqual(_read(claude), before)

        # A real drift is still repaired, and the hand-written lines survive.
        _write(claude, before.replace(b"@proj/AGENTS.md\n", b"", 1))
        rc, out, err = self.update(nested)
        self.assertEqual(rc, 0, out + err)
        text = _read(claude)
        self.assertEqual(text.count(b"@proj/AGENTS.md"), 1)
        self.assertTrue(text.endswith(mine), text)


class TestMultiRepoAnswerAllIsOrderIndependent(_StampBase):
    """Answering "A" to the multi-repo prompt registers every nested repo
    against the wrapper, whatever order find lists them in. _enroll_one keeps its
    state in globals, so a re-entrant call used to leak the previous repo into the
    next iteration: the wrapper resolved to the first nested repo, which then got
    a CLAUDE.md and a wrong pointer."""

    def _enroll_all(self, order):
        wrapper = os.path.join(self.tmpdir, "wrapper-" + order)
        repos = [os.path.join(wrapper, name) for name in ("alpha", "beta", "gamma")]
        os.makedirs(wrapper)
        for repo in repos:
            _init_repo(repo)
        path = self._find_stub(order) + os.pathsep + os.environ["PATH"]
        rc, out, err = self.run_cli_tty(["enroll", wrapper], cwd=wrapper, answer=b"A\n", PATH=path)
        self.assertEqual(rc, 0, out + err)
        return wrapper, repos

    def _check(self, order):
        wrapper, repos = self._enroll_all(order)
        pointer = _read(os.path.join(wrapper, ".clagentic-project")).decode().split()
        self.assertEqual(sorted(pointer), sorted(os.path.realpath(r) for r in repos), order)
        for repo in repos:
            for stray in (".clagentic-project", "CLAUDE.md", "AGENTS.md"):
                self.assertFalse(os.path.exists(os.path.join(repo, stray)),
                                 "%s: %s got %s" % (order, repo, stray))
        self.assertIn(MARKER, _read(os.path.join(wrapper, "CLAUDE.md")))

    def test_find_order_forward(self):
        self._check("forward")

    def test_find_order_reverse(self):
        self._check("reverse")


class TestEnrollStopsAtTheFirstFailure(_StampBase):
    """Each path (and each nested repo of an "A" answer) enrolls in its own
    subshell. The script runs under errexit, so a failing one must stop the run
    with a nonzero status and leave every later one unenrolled, as it did when a
    failure exited the whole script."""

    def _registry(self):
        path = os.path.join(self.home, ".local", "state", "clagentic", "registry")
        return _read(path).decode().split() if os.path.exists(path) else []

    def test_failing_first_path_stops_the_run(self):
        not_a_repo = os.path.join(self.tmpdir, "plain-dir")
        os.makedirs(not_a_repo)
        later = [os.path.join(self.tmpdir, name) for name in ("repo-one", "repo-two")]
        for repo in later:
            _init_repo(repo)
        rc, out, err = self.run_cli(["enroll", not_a_repo] + later, cwd=self.tmpdir)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("not a git repository", out + err)
        for repo in later:
            self.assertNotIn(os.path.realpath(repo), self._registry(), out + err)

    def test_failing_nested_repo_stops_the_all_loop(self):
        # The tool's own checkout is refused by enroll, which gives a real
        # failing nested repo. It is nested in this wrapper and sorts ahead of
        # the others under the forward find order.
        stub = self._find_stub("forward")
        later = [os.path.join(self.tmpdir, name) for name in ("xa", "xb")]
        for repo in later:
            _init_repo(repo)
        path = stub + os.pathsep + os.environ["PATH"]
        rc, out, err = self.run_cli_tty(["enroll", self.tmpdir], cwd=self.tmpdir,
                                        answer=b"A\n", PATH=path)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("refusing to enroll", out + err)
        for repo in later:
            self.assertNotIn(os.path.realpath(repo), self._registry(), out + err)
        pointer = _read(os.path.join(self.tmpdir, ".clagentic-project")).decode().split()
        for repo in later:
            self.assertNotIn(os.path.realpath(repo), pointer)


if __name__ == "__main__":
    import unittest
    unittest.main()
