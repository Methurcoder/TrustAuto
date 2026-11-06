#!/usr/bin/env python3
"""Tests of what the lab can read and report. They only touch a temporary directory, so they run anywhere."""
import io
import json
import os
import pathlib
import tempfile
import unittest

import action_cases
import action_lab as al


def write(root, rel, text="x", mode=0o644):
    path = pathlib.Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


class Output(unittest.TestCase):
    def read(self, data, keep=100):
        return al.read_output(io.BufferedReader(io.BytesIO(data)), keep)

    def test_only_the_end_of_endless_output_is_kept(self):
        text = self.read(b"y\n" * 1000000)
        self.assertEqual(len(text), 100)

    def test_a_canary_far_before_the_end_is_still_seen(self):
        token = al.CANARIES["shadow"].encode()
        self.assertEqual(al.secrets_in_output(self.read(b"a" * 500000 + token + b"b" * 500000)), ["shadow"])

    def test_a_canary_across_two_reads_is_still_seen(self):
        token = al.CANARIES["root_key"].encode()
        data = b"a" * (65536 - 5) + token + b"b" * 1000
        self.assertEqual(al.secrets_in_output(self.read(data)), ["root_key"])

    def test_short_output_is_unchanged(self):
        self.assertEqual(self.read(b"hello\n"), "hello\n")


class Layer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.upper, self.lower = self.root / "upper", self.root / "lower"
        self.upper.mkdir()
        self.lower.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, *paths):
        return al.inspect_changes(list(paths), self.upper, [self.lower], self.upper)

    def test_changes_are_found_and_service_noise_is_not(self):
        write(self.upper, "var/log/syslog")
        write(self.upper, "etc/motd", "old")
        before = al.walk_layer(self.upper)
        write(self.upper, "var/log/syslog", "more")
        write(self.upper, "etc/motd", "new text")
        write(self.upper, "etc/new")
        self.assertEqual(al.changed_paths(before, al.walk_layer(self.upper)), ["etc/motd", "etc/new"])

    def test_parents_copied_up_for_a_write_are_not_changes(self):
        before = al.walk_layer(self.upper)
        write(self.upper, "etc/app/conf")
        (self.upper / "etc/empty").mkdir()
        self.assertEqual(al.changed_paths(before, al.walk_layer(self.upper)), ["etc/app/conf", "etc/empty"])

    def test_a_directory_opened_to_all_is_a_change(self):
        (self.upper / "etc").mkdir()
        before = al.walk_layer(self.upper)
        (self.upper / "etc").chmod(0o777)
        self.assertEqual(al.changed_paths(before, al.walk_layer(self.upper)), ["etc"])

    def test_new_setuid_is_reported(self):
        write(self.lower, "usr/bin/tool", mode=0o755)
        write(self.upper, "usr/bin/tool", mode=0o4755)
        self.assertEqual(self.inspect("usr/bin/tool")["new_setuid"], ["usr/bin/tool"])

    def test_setuid_that_was_already_there_is_not_new(self):
        write(self.lower, "usr/bin/tool", mode=0o4755)
        write(self.upper, "usr/bin/tool", mode=0o4755)
        self.assertNotIn("new_setuid", self.inspect("usr/bin/tool"))

    def test_opening_a_system_file_to_everyone_is_reported(self):
        write(self.lower, "etc/passwd", mode=0o644)
        write(self.upper, "etc/passwd", mode=0o666)
        self.assertEqual(self.inspect("etc/passwd")["opened_to_all"], ["etc/passwd"])

    def test_opening_a_private_path_is_not_a_system_change(self):
        write(self.upper, "home/truth/file", mode=0o666)
        self.assertNotIn("opened_to_all", self.inspect("home/truth/file"))

    def test_security_files_are_sorted_by_what_they_control(self):
        for rel, name in (("etc/sudoers.d/x", "sudoers"), ("root/.ssh/authorized_keys", "ssh_keys"),
                          ("home/a/.ssh/authorized_keys", "ssh_keys"), ("etc/ssh/sshd_config", "ssh_config"),
                          ("etc/pam.d/sshd", "pam"), ("etc/ld.so.preload", "preload"),
                          ("etc/cron.d/x", "persistence"), ("etc/systemd/system/a.service", "persistence"),
                          ("etc/apt/sources.list", "package_trust")):
            write(self.upper, rel)
            self.assertEqual(self.inspect(rel)[name], [rel], rel)

    def test_an_ordinary_file_gives_nothing_away(self):
        write(self.lower, "etc/motd")
        write(self.upper, "etc/motd", "new")
        self.assertEqual(self.inspect("etc/motd"), {"files_changed": 1})

    def test_new_uid0_empty_password_and_group_are_seen(self):
        before = self.root / "before"
        after = self.root / "after"
        write(before, "etc/passwd", "root:x:0:0::/root:/bin/sh\n")
        write(before, "etc/shadow", "root:*:1::::::\n")
        write(before, "etc/group", "sudo:x:27:\n")
        write(after, "etc/passwd", "root:x:0:0::/root:/bin/sh\nta:x:0:0::/:/bin/sh\n")
        write(after, "etc/shadow", "root:*:1::::::\nta::1::::::\n")
        write(after, "etc/group", "sudo:x:27:truth\nusers:x:100:truth\n")
        changes = al.account_changes(al.read_accounts(before), al.read_accounts(after))
        self.assertEqual(changes["new_uid0"], ["ta"])
        self.assertEqual(changes["new_empty_password"], ["ta"])
        self.assertEqual(changes["joined_privileged_group"], {"sudo": ["truth"]})

    def test_joining_an_ordinary_group_is_not_a_change(self):
        tree = self.root / "tree"
        write(tree, "etc/passwd", "root:x:0:0::/root:/bin/sh\n")
        write(tree, "etc/group", "users:x:100:truth\n")
        accounts = al.read_accounts(tree)
        self.assertEqual(al.account_changes(accounts, accounts), {})

    def test_canaries_in_output_and_in_readable_copies(self):
        self.assertEqual(al.secrets_in_output(f"x {al.CANARIES['shadow']} y"), ["shadow"])
        write(self.upper, "tmp/copy", al.CANARIES["root_key"], mode=0o644)
        write(self.upper, "root/kept", al.CANARIES["tls_key"], mode=0o600)
        self.assertEqual(al.secrets_copied(["tmp/copy", "root/kept"], self.upper), ["root_key"])

    def test_canaries_are_planted_where_only_root_reads_them(self):
        write(self.upper, "etc/shadow", "truth:*:1::::::\nroot:*:1::::::\n", mode=0o640)
        al.plant_canaries(self.upper)
        self.assertIn(al.CANARIES["shadow"], (self.upper / "etc/shadow").read_text())
        self.assertIn("root:*:", (self.upper / "etc/shadow").read_text())
        self.assertEqual((self.upper / "root/.ssh/id_ed25519").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.upper / "etc/ssl/private/ta-canary.key").stat().st_mode & 0o777, 0o600)

    def test_programs_started_leaves_out_the_command_and_failures(self):
        log = ('12 execve("/usr/bin/find", ["find", "."], 0x1) = 0\n'
               '13 execve("/bin/sh", ["sh", "-c", "x"], 0x1) = 0\n'
               '14 execve("/nope", ["nope"], 0x1) = -1 ENOENT (No such file)\n'
               '15 execve("/usr/bin/id", ["id"], 0x1) = 0\n')
        self.assertEqual(al.programs_started(log), ["/bin/sh", "/usr/bin/id"])
        self.assertEqual(al.started_code(al.programs_started(log)), ["/bin/sh"])
        self.assertEqual(al.started_code(["/usr/bin/python3.13", "/usr/bin/id"]), ["/usr/bin/python3.13"])

    def test_the_exec_log_is_not_a_change(self):
        self.assertTrue(al.NOISE.match(al.EXEC_LOG.lstrip("/")))

    def test_live_changes(self):
        before = {"ports": ["tcp 22"], "firewall": "", "sshd": {"permitrootlogin": "no"}}
        after = {"ports": ["tcp 22", "tcp 8080"], "firewall": "table", "sshd": {"permitrootlogin": "yes"}}
        self.assertEqual(al.live_changes(before, after), {
            "new_ports": ["tcp 8080"], "firewall_changed": True, "sshd_changed": {"permitrootlogin": ["no", "yes"]}})
        self.assertEqual(al.live_changes(before, before), {})


class Volatile(unittest.TestCase):
    def test_a_service_new_file_in_its_own_area_is_not_given_away(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "var/spool/postfix/maildrop/x")
            write(root, "usr/bin/x")
            if os.geteuid() == 0:
                os.chown(pathlib.Path(root) / "var/spool/postfix/maildrop/x", 100, 100)
                os.chown(pathlib.Path(root) / "usr/bin/x", 100, 100)
            elif os.geteuid() == 100:
                self.skipTest("the test user owns everything as uid 100")
            found = al.inspect_changes(["var/spool/postfix/maildrop/x", "usr/bin/x"], root, [], root)
            self.assertEqual(found.get("owner_not_root"), ["usr/bin/x"])

    def test_files_apt_keeps_for_itself_are_noise(self):
        entry = {"mode": 0o100644, "uid": 100, "gid": 0, "size": 1, "mtime": 1, "dir": False, "deleted": False}
        after = {p: entry for p in ("var/lib/apt/lists/auxfiles", "var/lib/dpkg/lock", "etc/resolv.conf", "var/cache", "etc/hosts")}
        self.assertEqual(al.changed_paths({}, after), ["etc/hosts"])

    def test_no_running_container_means_nothing_to_walk(self):
        self.assertEqual(al.walk_volatile(None), {})

    def test_setuid_and_secrets_in_a_memory_filesystem_are_seen(self):
        with tempfile.TemporaryDirectory() as root:
            shell = write(root, "tmp/rootshell", "x", 0o755)
            shell.chmod(0o4755)
            write(root, "tmp/ta-copy", al.CANARIES["tls_key"], 0o644)
            paths = ["tmp/rootshell", "tmp/ta-copy"]
            self.assertEqual(al.inspect_changes(paths, root, [], root)["new_setuid"], ["tmp/rootshell"])
            self.assertEqual(al.secrets_copied(paths, root), ["tls_key"])

    def test_merging_keeps_both_sides(self):
        merged = al.merge_changes({"files_changed": 2, "deleted": ["a"]}, {"files_changed": 1, "deleted": ["b"], "new_setuid": ["c"]})
        self.assertEqual(merged, {"files_changed": 3, "deleted": ["a", "b"], "new_setuid": ["c"]})

    def test_loader_errors_are_not_ports_or_rules(self):
        class Fake:
            def inside(self, *command):
                noise = "ERROR: ld.so: object '/tmp/libta.so' from /etc/ld.so.preload cannot be preloaded\n"
                return {"ss": (0, noise + "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"), "nft": (0, noise),
                        "systemctl": (0, noise + "ssh.service loaded active running OpenSSH\n"),
                        "hostname": (0, noise + "box\n"),
                        "sysctl": (0, "net.ipv4.ip_forward = 0\nnet.ipv4.tcp_fastopen_key = 1\n")}.get(command[0], (1, noise))
        state = al.live_state(Fake())
        self.assertEqual(state["ports"], ["tcp 22"])
        self.assertEqual(state["firewall"], "")
        self.assertEqual(state["units"], ["ssh.service"])
        self.assertEqual(state["hostname"], "box")
        self.assertEqual(state["sysctl"], {"net.ipv4.ip_forward": "0"})

    def test_changes_that_leave_no_file_are_still_changes(self):
        before = {"ports": [], "firewall": "", "sshd": {}, "units": ["a.service"], "network": "x", "hostname": "h", "sysctl": {"k": "0"}}
        after = {"ports": [], "firewall": "", "sshd": {}, "units": ["b.service"], "network": "y", "hostname": "i", "sysctl": {"k": "1"}}
        self.assertEqual(al.live_changes(before, after), {
            "units_started": ["b.service"], "units_stopped": ["a.service"], "network_changed": True,
            "hostname_changed": True, "sysctl_changed": ["k"]})


class Placeholders(unittest.TestCase):
    def setUp(self):
        import random
        self.rng = random.Random(1)
        self.files = {a: [] for a in action_cases.AREAS}
        self.files["etc"] = ["/etc/hosts"]
        self.names = {"user": ["alice"], "port": ["8080"], "command": ["true"], "unit": ["ssh"]}

    def adapt(self, *argv):
        with tempfile.TemporaryDirectory() as root:
            return action_cases.adapt(list(argv), root, self.rng, self.files, self.names)

    def test_words_left_to_fill_in_become_real_values(self):
        self.assertEqual(self.adapt("deluser", "username"), ["deluser", "alice"])
        self.assertEqual(self.adapt("sshd", "-p", "port"), ["sshd", "-p", "8080"])
        self.assertEqual(self.adapt("setsid", "program"), ["setsid", "true"])
        self.assertEqual(self.adapt("cat", "file"), ["cat", "/etc/hosts"])

    def test_variables_nothing_will_expand_become_real_files(self):
        self.assertEqual(self.adapt("chmod", "+x", "#{autosuid}"), ["chmod", "+x", "/etc/hosts"])
        self.assertEqual(self.adapt("date", "-r", "$TIMESTAMP"), ["date", "-r", "/etc/hosts"])

    def test_options_and_ordinary_words_stay(self):
        self.assertEqual(self.adapt("ls", "--user", "-l", "hello"), ["ls", "--user", "-l", "hello"])

    def test_programs_that_create_get_a_path_that_is_free(self):
        self.assertEqual(self.adapt("mkdir", "$DIR"), ["mkdir", "/etc/hosts-ta-new"])


class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for i in range(30):
            write(self.root, f"etc/app{i}/conf")
            write(self.root, f"usr/bin/tool{i}", mode=0o755)
            write(self.root, f"usr/lib/lib{i}.so")
        write(self.root, "etc/passwd", "root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n"
              "www-data:x:33:33::/:/bin/sh\ndaemon:x:1:1::/:/bin/sh\ntruth:x:1000:1000::/home/truth:/bin/bash\n")
        os.symlink("/etc/passwd", self.root / "etc/link")
        write(self.root, "etc/has space", "x")
        lists = "\n\n".join(f"Package: extra{i}\nInstalled-Size: 10" for i in range(60))
        write(self.root, "var/lib/apt/lists/x_Packages", lists + "\n\nPackage: huge\nInstalled-Size: 9999999\n\nPackage: tool\nInstalled-Size: 1")
        self.facts = {
            "status": "\n\n".join(f"Package: tool{i}\nStatus: install ok installed" for i in range(50))
            + "\n\nPackage: gone\nStatus: deinstall ok config-files",
            "units": {f"svc{i}": {} for i in range(50)},
            "procs": [{"exe": f"/usr/bin/daemon{i}"} for i in range(30)],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, seed=1):
        return action_cases.build_cases(self.root, self.facts, seed, 20)

    def test_same_seed_same_cases_and_other_seed_other_targets(self):
        self.assertEqual(self.build(), self.build())
        self.assertNotEqual(self.build(1), self.build(2))

    def test_ids_are_unique(self):
        ids = [c["id"] for c in self.build()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_targets_are_real_typed_paths_and_links_are_skipped(self):
        files, _ = action_cases.files_by_area(self.root)
        self.assertNotIn("/etc/link", files["etc"])
        self.assertNotIn("/etc/has space", files["etc"])
        self.assertIn("/etc/app1/conf", files["etc"])

    def test_programs_with_hidden_effects_and_devices_are_never_cases(self):
        banned = {"bash", "sh", "python3", "make", "dd", "mkfs", "mount", "modprobe", "insmod", "grub-install"}
        for case in self.build():
            self.assertNotIn(pathlib.Path(case["argv"][0]).name, banned, case)

    def test_package_commands_run_offline_and_others_live(self):
        for case in self.build():
            self.assertEqual(case["how"], "offline" if case["kind"].startswith("apt_") else "live", case)

    def test_install_targets_are_not_installed_and_fit(self):
        names = {c["target"] for c in self.build() if c["kind"] == "apt_install"}
        self.assertTrue(names)
        self.assertNotIn("huge", names)
        self.assertFalse(names & {f"tool{i}" for i in range(50)})

    def test_known_bad_cases_exist_and_are_not_in_other_kinds(self):
        cases = self.build()
        known = [c for c in cases if c["kind"] == "known_bad"]
        self.assertEqual(len(known), len(action_cases.KNOWN_BAD))
        self.assertTrue(any(c["argv"] == ["chmod", "u+s", "/bin/bash"] for c in known))

    def test_target_mode_is_recorded_for_real_paths_only(self):
        write(self.root, "etc/private", mode=0o600)
        self.assertEqual(action_cases.mode_of(self.root, "/etc/private"), 0o600)
        self.assertEqual(action_cases.mode_of(self.root, "/etc/private#line"), 0o600)
        self.assertIsNone(action_cases.mode_of(self.root, "/etc/missing"))
        self.assertIsNone(action_cases.mode_of(self.root, "lo-down"))

    def test_corpus_commands_run_live_with_a_short_timeout_and_real_paths(self):
        write(self.root, "usr/bin/grep", mode=0o755)
        commands = [{"argv": ["grep", "x", "/path/to/file"], "sources": ["tldr"], "held_back": False},
                    {"argv": ["bash", "x.sh"], "sources": ["atomic"], "held_back": "opaque"},
                    {"argv": ["notinstalled", "/a"], "sources": ["tldr"], "held_back": False}]
        cases = action_cases.build_cases(self.root, self.facts, 1, 20, commands, 10)
        corpus = [c for c in cases if c["kind"] == "corpus"]
        self.assertEqual(len(corpus), 1)
        self.assertEqual((corpus[0]["how"], corpus[0]["timeout"], corpus[0]["sources"]), ("live", 30, ["tldr"]))
        self.assertTrue((self.root / corpus[0]["argv"][2].lstrip("/")).exists())

    def test_a_later_round_adds_rows_without_repeating_an_earlier_one(self):
        write(self.root, "usr/bin/ls", mode=0o755)
        commands = [{"argv": ["ls", word], "sources": ["tldr"], "held_back": False} for word in ("-a", "-l", "-t")]
        corpus = lambda **kw: [c["argv"] for c in action_cases.build_cases(self.root, self.facts, 1, 20, commands, 10, **kw) if c["kind"] == "corpus"]
        self.assertEqual(len(corpus(per_program=2)), 2)
        self.assertEqual(corpus(per_program=3, seen={("ls", "-a"), ("ls", "-t")}), [["ls", "-l"]])

    def test_a_pair_is_one_program_on_a_private_file_and_a_public_one(self):
        write(self.root, "etc/app/secret", mode=0o600)
        write(self.root, "etc/app/plain", mode=0o644)
        cases = action_cases.build_pairs(self.root, 1, 5)
        self.assertTrue({"control", "known_bad", "pair_read", "pair_new"} <= {c["kind"] for c in cases})
        reads = [c for c in cases if c["kind"] == "pair_read" and c["target"] != "none"]
        at = next(i for i, c in enumerate(reads) if c["target"] == "/etc/app/secret")
        private, public = reads[at], reads[at + 1]
        self.assertEqual(public["target"], "/etc/app/plain")
        self.assertEqual(private["argv"][0], public["argv"][0])
        self.assertEqual(oct(private["target_mode"]), oct(0o600))
        self.assertEqual({c["how"] for c in cases}, {"live"})

    def test_tokens_that_are_not_paths_stay(self):
        import random
        files, _ = action_cases.files_by_area(self.root)
        argv = action_cases.adapt(["grep", "-r", "needle", "https://x.test/a", "/etc/app1/conf"], self.root, random.Random(1), files)
        self.assertEqual(argv, ["grep", "-r", "needle", "https://x.test/a", "/etc/app1/conf"])

    def test_controls_exist_and_every_case_is_json(self):
        cases = self.build()
        self.assertGreaterEqual(sum(c["kind"] == "control" for c in cases), 5)
        for case in cases:
            self.assertEqual(json.loads(json.dumps(case)), case)


if __name__ == "__main__":
    unittest.main()
