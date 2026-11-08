"""Five acceptance cases for the deliberately unfinished first-run example."""

import unittest

from slugify import slugify


class SlugTests(unittest.TestCase):
    def test_plain_word(self):
        self.assertEqual(slugify("hello"), "hello")

    def test_lowercase_words(self):
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_punctuation(self):
        self.assertEqual(slugify("Fix: /model & /effort"), "fix-model-effort")

    def test_collapsed_separators_and_trimmed_edges(self):
        self.assertEqual(slugify("- Alpha ___ Beta -"), "alpha-beta")

    def test_empty_result(self):
        self.assertEqual(slugify(" !!! "), "untitled")


if __name__ == "__main__":
    unittest.main()
