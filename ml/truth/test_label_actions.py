#!/usr/bin/env python3
"""Each observation must lead to the label docs/ML_OUTSIDE_RULES_PLAN.md gives it."""
import unittest

import label_actions as la

BASELINE = {"ssh_login", "sudo"}


def row(kind="rm_file", rc=0, changes=None, paths=(), accounts=None, live=None, started=(), shown=(), copied=(),
        mode=0o644, sources=(), tail="", checks=None, how="live", programs=()):
    return {"id": "x", "kind": kind, "argv": ["cmd"], "sources": list(sources), "target_mode": mode, "how": how,
            "action": {"rc": rc, "tail": tail, "secrets_in_output": list(shown), "started_code": list(started),
                       "programs": programs},
            "checks_now": checks, "checks_after_boot": None,
            "result": {"changes": changes or {}, "accounts": accounts or {}, "secrets_copied": list(copied),
                       "changed_paths": list(paths), "live": live or {}}}


class Labels(unittest.TestCase):
    def assertLabel(self, r, wanted):
        self.assertEqual(la.label(r, BASELINE)[0], wanted, la.label(r, BASELINE)[1])

    def test_nothing_changed_is_harmless(self):
        self.assertLabel(row(), "harmless")

    def test_a_check_that_passed_before_and_fails_now_is_risky(self):
        self.assertLabel(row(checks={"sudo": False}), "risky")

    def test_a_check_that_never_passed_says_nothing(self):
        self.assertLabel(row(checks={"role_dns": False}), "harmless")

    def test_everything_given_away_is_risky(self):
        for key in la.BAD_CHANGES:
            self.assertLabel(row(changes={key: ["a"]}, paths=["a"]), "risky")
        self.assertLabel(row(accounts={"new_uid0": ["x"]}, paths=["etc/passwd"]), "risky")
        self.assertLabel(row(live={"new_ports": ["tcp 1"]}), "risky")
        self.assertLabel(row(live={"sshd_changed": {"a": [1, 2]}}), "risky")
        self.assertLabel(row(shown=["shadow"]), "risky")
        self.assertLabel(row(copied=["shadow"], paths=["tmp/x"]), "risky")

    def test_a_shell_started_is_risky_except_from_package_scripts(self):
        self.assertLabel(row(started=["/bin/sh"]), "risky")
        self.assertLabel(row(kind="apt_install", started=["/bin/sh"], how="offline"), "harmless")

    def test_reading_a_private_file_is_risky_and_a_public_one_is_not(self):
        self.assertLabel(row(kind="read_file", mode=0o600), "risky")
        self.assertLabel(row(kind="read_file", mode=0o644), "harmless")

    def test_a_failed_read_of_a_private_file_gave_nothing_away(self):
        self.assertLabel(row(kind="read_file", mode=0o600, rc=1), "review")

    def test_cron_is_risky_and_unit_links_go_to_the_teacher(self):
        self.assertLabel(row(changes={"persistence": ["etc/cron.d/x"]}, paths=["etc/cron.d/x"]), "risky")
        self.assertLabel(row(changes={"persistence": ["etc/systemd/system/x"]}, paths=["etc/systemd/system/x"]), "teacher")

    def test_small_changes_go_to_the_teacher_and_large_ones_to_review(self):
        self.assertLabel(row(paths=["srv/a"]), "teacher")
        self.assertLabel(row(paths=[f"srv/{i}" for i in range(la.TEACHER_MAX_FILES + 1)]), "review")
        self.assertLabel(row(kind="apt_install", paths=[f"srv/{i}" for i in range(la.TEACHER_MAX_FILES + 1)]), "teacher")

    def test_state_that_leaves_no_file_is_not_harmless(self):
        for key in ("units_stopped", "units_started", "sysctl_changed"):
            self.assertLabel(row(live={key: ["a"]}), "teacher")
        self.assertLabel(row(live={"hostname_changed": True}), "teacher")
        self.assertLabel(row(live={"network_changed": True}), "teacher")

    def test_a_failure_tells_nothing(self):
        self.assertLabel(row(rc=1), "review")
        self.assertLabel(row(rc=124), "review")

    def test_a_missing_program_is_not_used_at_all(self):
        self.assertLabel(row(rc=127), "unusable")
        self.assertLabel(row(rc=1, tail="strace: Can't stat '/x': No such file or directory"), "unusable")
        self.assertEqual(la.label({"id": "x", "kind": "corpus", "argv": [], "error": "boom"}, BASELINE)[0], "unusable")

    def test_an_escape_recipe_with_no_shell_proves_nothing(self):
        self.assertLabel(row(sources=["gtfobins"]), "review")
        self.assertLabel(row(sources=["gtfobins"], started=["/bin/sh"]), "risky")

    def test_no_exec_log_means_it_cannot_be_called_harmless(self):
        self.assertLabel(row(programs=None), "review")

    def test_a_private_target_of_a_corpus_command_goes_to_review(self):
        self.assertLabel(row(kind="corpus", mode=0o600), "review")


class Noise(unittest.TestCase):
    def test_what_changed_in_controls_is_not_held_against_a_command(self):
        rows = [row(kind="control", paths=["var/lib/x"], live={"units_started": ["t.timer"]}),
                row(paths=["var/lib/x"], live={"units_started": ["t.timer"]}), row(paths=["var/lib/x", "srv/a"])]
        labelled = la.label_all(rows, BASELINE)
        self.assertEqual(labelled[1]["label"], "harmless")
        self.assertEqual(labelled[2]["label"], "teacher")
        self.assertEqual(labelled[2]["reasons"], ["files:1"])


class Faults(unittest.TestCase):
    def test_a_missed_known_bad_and_a_dirty_control_are_lab_faults(self):
        rows = la.label_all([row(kind="known_bad"), row(kind="control", rc=1)], BASELINE)
        self.assertEqual(len(la.lab_faults(rows)), 2)

    def test_a_caught_known_bad_is_no_fault(self):
        rows = la.label_all([row(kind="known_bad", shown=["shadow"]), row(kind="control")], BASELINE)
        self.assertEqual(la.lab_faults(rows), [])

    def test_a_known_bad_caught_only_because_the_lab_could_not_restart_it_is_a_fault(self):
        rows = la.label_all([{**row(kind="known_bad", shown=["shadow"]), "reasons": []}], BASELINE)
        rows[0]["reasons"] = ["check:boot", "secret_shown:shadow"]
        self.assertEqual(len(la.lab_faults(rows)), 1)


if __name__ == "__main__":
    unittest.main()
