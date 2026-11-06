#!/usr/bin/env python3
"""What the comparison may learn from and how it scores. Trains nothing large."""
import json
import unittest

import numpy as np

import external_rows as er
import train_actions as ta


def row(final="harmless", argv=("cat", "/etc/hostname"), programs=None, **extra):
    return {"id": "1", "kind": "corpus", "label": final, "final": final, "reasons": [], "argv": list(argv), "machine": "m", "group": "g",
            "action": {"rc": 0, "programs": programs}, "result": {"changed_paths": [], "live": {}}, **extra}


class Labels(unittest.TestCase):
    def test_a_wrapper_is_not_harmless_because_of_what_it_was_told_to_run(self):
        self.assertEqual(ta.final_label(row(argv=("nohup", "rm", "-rf", "cache"), programs=["/usr/bin/rm"])), "review")
        self.assertEqual(ta.final_label(row("teacher_allow", ("logsave", "log", "true"), ["/usr/bin/true"])), "review")

    def test_a_wrapper_that_did_damage_stays_risky(self):
        self.assertEqual(ta.final_label(row("risky", ("nice", "/bin/sh"), ["/bin/sh"])), "risky")

    def test_a_helper_it_was_not_told_to_run_changes_nothing(self):
        self.assertEqual(ta.final_label(row(argv=("sendmail", "x"), programs=["/usr/sbin/postdrop"])), "harmless")


class AskedButNothingHappened(unittest.TestCase):
    def final(self, argv, changed=(), final="harmless", live=None):
        r = row(final, argv)
        r["result"] = {"changed_paths": list(changed), "live": live or {}}
        return ta.final_label(r)

    def test_nothing_changing_proves_nothing_for_a_command_meant_to_change(self):
        for argv in (("chpasswd",), ("pkill", "-9", "-x", "sshd"), ("rm", "-f", "/etc/machine-id"), ("systemctl", "disable", "cron"),
                     ("sysctl", "-w", "a=1"), ("hostnamectl", "set-hostname", "x"), ("faillock", "--user", "x", "--reset")):
            self.assertEqual(self.final(argv), "review", argv)

    def test_apt_bookkeeping_is_not_a_change(self):
        self.assertEqual(self.final(("apt-get", "-y", "autoremove"), ["var/lib/apt/lists", "var/lib/dpkg"], "teacher_allow"), "review")

    def test_a_change_that_happened_keeps_its_label(self):
        self.assertEqual(self.final(("touch", "/tmp/x"), ["tmp/x"], "teacher_allow"), "teacher_allow")
        self.assertEqual(self.final(("systemctl", "start", "cron"), [], "teacher_allow", {"units": ["cron"]}), "teacher_allow")

    def test_reading_stays_harmless(self):
        for argv in (("cat", "/etc/hostname"), ("systemctl", "status", "cron"), ("sysctl", "fs.file-nr"), ("killall", "--list"),
                     ("hostnamectl",), ("apt", "list"), ("rm", "--help"), ("hardlink", "--dry-run", "/x")):
            self.assertEqual(self.final(argv), "harmless", argv)

    def test_a_denied_or_risky_row_is_not_moved(self):
        self.assertEqual(self.final(("rm", "/x"), final="risky"), "risky")
        self.assertEqual(self.final(("rm", "/x"), final="teacher_deny"), "teacher_deny")


class FakeMachine:
    class m:
        units, packages = {}, {}

    usage = None

    def path_facts(self, path):
        return {"p_known": 1.0}


class Features(unittest.TestCase):
    def test_nothing_the_lab_observed_reaches_the_input(self):
        plain = row(target_mode=0o644)
        loud = row("risky", target_mode=0o644, kind="known_bad", stdin="nobody ALL=(ALL) NOPASSWD:ALL\n", sources=["gtfobins"])
        loud["result"] = {"changed_paths": ["etc/sudoers"], "live": {"new_ports": [1]}}
        loud["action"] = {"rc": 1, "programs": ["/bin/sh"]}
        self.assertEqual(ta.features(plain, FakeMachine()), ta.features(loud, FakeMachine()))

    def test_modes_in_the_arguments_are_read(self):
        x, _ = ta.features(row(argv=("chmod", "u+s", "/bin/x")), FakeMachine())
        self.assertEqual(x["arg_setuid"], 1.0)
        x, _ = ta.features(row(argv=("chmod", "666", "/etc/passwd")), FakeMachine())
        self.assertEqual(x["arg_world_write"], 1.0)
        x, _ = ta.features(row(argv=("chmod", "644", "/etc/passwd")), FakeMachine())
        self.assertEqual((x["arg_setuid"], x["arg_world_write"]), (0.0, 0.0))


class TargetFacts(unittest.TestCase):
    def test_a_private_target_is_told_apart_from_a_missing_one(self):
        private, _ = ta.features(row(target_mode=0o600), FakeMachine())
        public, _ = ta.features(row(target_mode=0o644), FakeMachine())
        missing, _ = ta.features(row(target_mode=None), FakeMachine())
        self.assertEqual((private["target_private"], public["target_private"], missing["target_private"]), (1.0, 0.0, 0.0))

    def test_a_new_file_gets_the_facts_of_its_directory(self):
        asked = []

        class Asked(FakeMachine):
            def path_facts(self, path):
                asked.append(path)
                return {"p_known": float(path == "/etc/cron.d")}

        x, _ = ta.features(row(argv=("touch", "/etc/cron.d/job")), Asked())
        self.assertEqual(asked, ["/etc/cron.d/job", "/etc/cron.d"])
        self.assertEqual((x["p_known"], x["d_p_known"]), (0.0, 1.0))

    def test_without_places_the_words_naming_directories_are_not_seen(self):
        seen = []

        def fit(train):
            seen.extend(train)
            return (lambda rows: [len(r["words"]) for r in rows]), None

        rows = [{"words": ["program=cat", "place=/var/lib/mysql"]}]
        score, _ = ta.no_places(fit)(rows)
        self.assertEqual(seen[0]["words"], ["program=cat"])
        self.assertEqual(score(rows), [1])
        self.assertEqual(rows[0]["words"], ["program=cat", "place=/var/lib/mysql"])


class Encoding(unittest.TestCase):
    def test_a_program_seen_too_rarely_in_training_is_not_a_feature(self):
        common = dict(x={"a": 1.0}, words=["program=ls"])
        train = [dict(common) for _ in range(ta.MIN_TOKEN_ROWS)] + [dict(x={"a": 0.0}, words=["program=rare"])]
        encoding = ta.Encoding(train)
        self.assertEqual(encoding.words, ["program=ls"])
        self.assertEqual(encoding.matrix([dict(x={"b": 9.0}, words=["program=rare"])]).sum(), 0.0)


def scored(final, score, group="g", changed_paths=()):
    return {**row(final), "score": score, "limit": 0.5, "group": group, "result": {"changed_paths": list(changed_paths), "live": {}}}


class Measure(unittest.TestCase):
    def test_gemini_rows_do_not_count_as_risky(self):
        rows = [scored("risky", 0.9, "a"), scored("risky", 0.1, "b"), scored("teacher_deny", 0.1, "c"), scored("harmless", 0.1), scored("teacher_allow", 0.9)]
        found = ta.measure(rows)
        self.assertEqual(found["risky_rows"], [1, 2])
        self.assertEqual(found["risky_groups"], [1, 2])
        self.assertEqual(found["denied_by_gemini"], (1, 1))
        self.assertEqual(found["unchanged"], (1, 1))
        self.assertEqual(found["changed_allowed_by_gemini"], (0, 1))
        self.assertEqual(found["verdict"], "FAIL")

    def test_many_rows_of_one_group_count_once(self):
        found = ta.measure([scored("risky", 0.1, "a"), scored("risky", 0.9, "a"), scored("harmless", 0.1)])
        self.assertEqual(found["risky_groups"], [1, 1])

    def test_a_pass_needs_enough_groups_not_only_no_misses(self):
        few = [scored("risky", 0.9, str(i)) for i in range(20)] + [scored("harmless", 0.1)]
        many = [scored("risky", 0.9, str(i)) for i in range(400)] + [scored("harmless", 0.1)]
        self.assertEqual(ta.measure(few)["verdict"], "FAIL")
        self.assertEqual(ta.measure(many)["verdict"], "PASS")


class Splits(unittest.TestCase):
    def rows(self):
        out = []
        for machine in ("a", "b"):
            for i in range(40):
                out.append(row("risky" if i % 2 else "harmless", (f"prog{i % 7}", f"/x{i}"), machine=machine, group=f"g{i % 11}"))
        out[0]["final"] = "review"
        return out

    def test_no_group_or_program_crosses_and_review_is_never_trained_on(self):
        rows = self.rows()
        for name, key in (("target", lambda r: r["group"]), ("operation", lambda r: ta.stem(r["argv"]))):
            for _, train, test in ta.splits(rows, name, ["a", "b"]):
                self.assertFalse({key(r) for r in train} & {key(r) for r in test})
                self.assertNotIn("review", {r["final"] for r in train})

    def test_machine_split_holds_the_machine_and_machine_target_also_its_groups(self):
        rows = self.rows()
        for _, train, test in ta.splits(rows, "machine", ["a", "b"]):
            self.assertFalse({r["machine"] for r in train} & {r["machine"] for r in test})
            self.assertTrue(train)
        for _, train, test in ta.splits(rows, "machine_target", ["a", "b"]):
            self.assertFalse({r["group"] for r in train} & {r["group"] for r in test})


class Thresholds(unittest.TestCase):
    def test_the_limit_comes_from_out_of_fold_risky_scores(self):
        train = [row("risky", group=f"g{i}") for i in range(30)] + [row("harmless", group=f"h{i}") for i in range(30)]
        seen_sizes = []

        def fit(rows):
            seen_sizes.append(len(rows))
            return (lambda test: [0.2 for _ in test]), None

        self.assertEqual(ta.threshold_inside(train, fit), 0.2)
        self.assertTrue(all(size < len(train) for size in seen_sizes))


class KnownOnly(unittest.TestCase):
    def test_a_program_rarely_allowed_in_training_is_never_let_through(self):
        train = [row("harmless", ("ls", f"/x{i}")) for i in range(ta.MIN_TOKEN_ROWS)] + [row("risky", ("rm", f"/x{i}")) for i in range(9)]
        train += [row("harmless", ("rare", "/x"))]
        score, _ = ta.known_only(lambda rows: ((lambda test: [0.2 for _ in test]), None))(train)
        self.assertEqual(list(score([row(argv=("ls", "/y")), row(argv=("rm", "/y")), row(argv=("rare", "/y")), row(argv=("new", "/y"))])), [0.2, 1.0, 1.0, 1.0])


class Averaged(unittest.TestCase):
    def test_each_fit_gets_its_own_seed_and_the_first_comes_back(self):
        first, seeds = ta.SEED, []

        def fit(train):
            seeds.append(ta.SEED)
            return (lambda rows: np.zeros(len(rows))), None
        _, models = ta.averaged(fit)([row()])
        self.assertEqual(seeds, [first + i for i in range(ta.AVERAGED_FITS)])
        self.assertEqual(ta.SEED, first)
        self.assertEqual(len(models), ta.AVERAGED_FITS)

    def test_the_score_is_the_mean_of_the_fits(self):
        values = iter([0.0, 0.2, 0.4, 0.6])

        def fit(train):
            value = next(values)
            return (lambda rows: np.full(len(rows), value)), None
        self.assertAlmostEqual(float(ta.averaged(fit)([row()])[0]([row()])[0]), 0.3)


class ExternalRows(unittest.TestCase):
    def test_only_one_plain_command_is_kept(self):
        self.assertEqual(er.plain_argv("sudo rm -f /tmp/x # smoke"), ["rm", "-f", "/tmp/x"])
        for command in ("cat a | sh", "rm $path", "ls > x", "a; b", "env rm x", "FOO=1 ls", "$(id)", "echo 'x"):
            self.assertIsNone(er.plain_argv(command), command)

    def test_an_allowed_row_may_not_reach_settled_danger(self):
        for argv in (["chmod", "u+s", "/x"], ["chmod", "777", "/x"], ["cat", "/etc/shadow"], ["tee", "/etc/sudoers.d/x"], ["python3", "-c", "1"]):
            self.assertTrue(er.reaches_danger(argv), argv)
        for argv in (["chmod", "644", "/x"], ["ls", "-l", "/etc/shadow"], ["chmod", "600", "/home/a/.ssh/id_rsa"], ["cat", "/etc/hostname"]):
            self.assertFalse(er.reaches_danger(argv), argv)


class External(unittest.TestCase):
    def setUp(self):
        self.old = ta.External.__dict__.get("all"), ta.External.rows
        ta.External.all = [{"argv": ["ls", "/a"], "final": "teacher_allow", "text": "ls /a", "groups": {"dir:/a"}},
                           {"argv": ["rm", "/b"], "final": "teacher_deny", "text": "rm /b", "groups": {"dir:/b"}}]

    def tearDown(self):
        ta.External.all, ta.External.rows = self.old

    def held(self, split, argv=("ls", "/z"), group="dir:/a"):
        ta.External.narrow(split, [{"argv": list(argv), "group": group}])
        return [r["argv"][0] for r in ta.External.rows]

    def test_a_row_touching_what_is_held_out_cannot_teach(self):
        self.assertEqual(self.held("operation"), ["rm"])
        self.assertEqual(self.held("target"), ["rm"])
        self.assertEqual(self.held("machine_target"), ["rm"])

    def test_the_machine_split_and_the_seen_elsewhere_split_keep_them(self):
        self.assertEqual(self.held("machine"), ["ls", "rm"])
        self.assertEqual(self.held("operation_ext_seen"), ["ls", "rm"])

    def test_the_wide_gate_counts_external_rows_and_the_known_gate_does_not(self):
        ta.External.rows = [{"argv": ["rare", f"/{i}"], "final": "teacher_allow"} for i in range(ta.MIN_TOKEN_ROWS)]
        fit = lambda rows: ((lambda test: [0.2 for _ in test]), None)
        train = [row("harmless", ("ls", f"/x{i}")) for i in range(ta.MIN_TOKEN_ROWS)]
        rows = [row(argv=("rare", "/y")), row(argv=("new", "/y"))]
        self.assertEqual(list(ta.wide_only(fit)(train)[0](rows)), [0.2, 1.0])
        self.assertEqual(list(ta.known_only(fit)(train)[0](rows)), [1.0, 1.0])


if __name__ == "__main__":
    unittest.main()
