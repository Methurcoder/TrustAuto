#!/usr/bin/env python3
import unittest

import merge_rounds


def lab(id, *argv, stdin=""):
    return {"id": id, "argv": list(argv), "stdin": stdin, "label": "teacher"}


class Merge(unittest.TestCase):
    def test_a_later_round_gets_new_ids_and_keeps_its_answers(self):
        first = ([lab("00001-a", "ls")], [{"id": "00001-a", "final": "teacher_allow"}])
        second = ([lab("00001-a", "pwd")], [{"id": "00001-a", "final": "teacher_deny"}])
        rows, taught, repeats = merge_rounds.merge([first, second])
        self.assertEqual([r["id"] for r in rows], ["00001-a", "r2-00001-a"])
        self.assertEqual(taught[1], {"id": "r2-00001-a", "final": "teacher_deny"})
        self.assertEqual(repeats, 0)

    def test_a_repeat_keeps_the_earlier_row_and_its_answer(self):
        first = ([lab("00001-a", "ls")], [{"id": "00001-a", "final": "teacher_allow"}])
        second = ([lab("00009-b", "ls")], [{"id": "00009-b", "final": "teacher_deny"}])
        rows, taught, repeats = merge_rounds.merge([first, second])
        self.assertEqual([r["id"] for r in rows], ["00001-a"])
        self.assertEqual([t["final"] for t in taught], ["teacher_allow"])
        self.assertEqual(repeats, 1)

    def test_other_stdin_is_another_command(self):
        rows, _, repeats = merge_rounds.merge([([lab("1", "tee", stdin="a"), lab("2", "tee", stdin="b")], [])])
        self.assertEqual((len(rows), repeats), (2, 0))


if __name__ == "__main__":
    unittest.main()
