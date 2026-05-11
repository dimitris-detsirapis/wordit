import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from wordit import (
    BuildOptions,
    LinkExtractor,
    TextExtractor,
    WorditShell,
    ai_provider_label,
    ai_keyword_prompt,
    build_profile_wordlist,
    load_ai_config,
    mask_secret,
    read_ai_config,
    estimate_mask_collection_keyspace,
    escape_mask_literal,
    extract_words,
    generate_from_mask,
    generate_huge_masks,
    generate_hashcat_rules,
    github_profile_to_harvest_text,
    leet_variants,
    mask_keyspace,
    mutate_wordlist,
    github_profile_name,
    normalize_harvest_target,
    option_preset,
    parse_ai_keywords,
    path_completions,
    url_hint_text,
    write_ai_config,
)


class WorditTests(unittest.TestCase):
    def test_extract_words_deduplicates_and_filters(self):
        words = extract_words("Alpha alpha beta42 x 123", min_len=2, include_numbers=False)
        self.assertEqual(words, ["alpha", "beta42"])

    def test_leet_variants_are_bounded(self):
        variants = leet_variants("toast", depth=1)
        self.assertIn("t0ast", variants)
        self.assertIn("toa5t", variants)

    def test_mask_count_and_generation(self):
        self.assertEqual(mask_keyspace("?1?d", {"1": "ab"}), 20)
        generated = generate_from_mask("?1?d", {"1": "ab"}, limit=4)
        self.assertEqual(generated, ["a0", "a1", "a2", "a3"])

    def test_profile_generation_includes_dates_and_case(self):
        options = BuildOptions(
            min_len=4,
            max_len=20,
            max_candidates=1000,
            years=("2026",),
            leet_depth=0,
        )
        words = build_profile_wordlist({"names": "Alice", "dates": "2026-05-11"}, options)
        self.assertIn("alice2026", words)
        self.assertIn("Alice2026", words)

    def test_profile_generation_tries_numbers_between_words(self):
        options = option_preset("focused", max_candidates=2000)
        words = build_profile_wordlist({"extras": "paok paokara"}, options)
        self.assertIn("paok4paokara", words)

    def test_profile_uses_numbers_from_hints_between_words(self):
        options = option_preset("numbers", max_candidates=2000)
        words = build_profile_wordlist({"extras": "paok 13 paokara"}, options)
        self.assertIn("paok13paokara", words)

    def test_mutation_appends_years_and_symbols(self):
        options = BuildOptions(
            min_len=4,
            max_len=20,
            max_candidates=100,
            years=("2026",),
            symbols=("!",),
            leet_depth=0,
            include_pairs=False,
        )
        words = mutate_wordlist(["Acme"], options)
        self.assertIn("Acme2026", words)
        self.assertIn("Acme2026!", words)

    def test_numbers_style_does_not_add_symbols(self):
        options = option_preset("numbers", max_candidates=500)
        words = mutate_wordlist(["paok", "paokara"], options)
        self.assertIn("paok4", words)
        self.assertIn("paok4paokara", words)
        self.assertNotIn("paok!", words)
        self.assertNotIn("paok_paokara", words)

    def test_advanced_menu_uses_local_numbers_and_back(self):
        shell = WorditShell()
        output = StringIO()
        with redirect_stdout(output):
            shell.do_advanced("")
        self.assertEqual(shell.menu_mode, "advanced")
        self.assertIn("[1] Harvest words", output.getvalue())
        self.assertIn("[3] AI smart harvest", output.getvalue())
        self.assertIn("[4] AI API setup", output.getvalue())
        self.assertNotIn("[21]", output.getvalue())

        output = StringIO()
        with redirect_stdout(output):
            shell.do_use("0")
        self.assertEqual(shell.menu_mode, "main")
        self.assertIn("Main menu", output.getvalue())

    def test_path_completions_include_files_and_navigable_dirs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "words.txt")
            dir_path = os.path.join(temp_dir, "lists")
            open(file_path, "w", encoding="utf-8").close()
            os.mkdir(dir_path)

            matches = path_completions(os.path.join(temp_dir, ""))

        self.assertIn(file_path, matches)
        self.assertIn(dir_path + os.sep, matches)

    def test_url_hints_split_profile_path_words(self):
        text = url_hint_text("https://github.com/dimitris-destirapis")
        self.assertIn("dimitris", text)
        self.assertIn("destirapis", text)
        self.assertIn("dimitrisdestirapis", text)

    def test_url_target_normalization_and_github_profile_detection(self):
        self.assertEqual(normalize_harvest_target("github.com/octocat"), "https://github.com/octocat")
        self.assertEqual(github_profile_name("https://github.com/octocat"), "octocat")
        self.assertIsNone(github_profile_name("https://github.com/topics/python"))

    def test_github_profile_text_keeps_useful_fields_only(self):
        text = github_profile_to_harvest_text(
            {
                "login": "octocat",
                "name": "The Octocat",
                "location": "San Francisco",
                "bio": "GitHub mascot",
                "followers_url": "https://api.github.com/users/octocat/followers",
                "id": 583231,
            }
        )
        self.assertIn("octocat", text)
        self.assertIn("San Francisco", text)
        self.assertNotIn("followers", text)
        self.assertNotIn("583231", text)

    def test_html_extractor_reads_meta_and_alt_text(self):
        parser = TextExtractor()
        parser.feed(
            '<html><head><meta name="description" content="Dimitris security profile"></head>'
            '<body><img alt="kista project"><script>ignore_me</script></body></html>'
        )
        text = parser.text()
        self.assertIn("Dimitris security profile", text)
        self.assertIn("kista project", text)
        self.assertNotIn("ignore_me", text)

    def test_link_extractor_normalizes_links(self):
        parser = LinkExtractor("https://example.com/base/page.html")
        parser.feed('<a href="/profile">Profile</a><a href="#local">Local</a><a href="mailto:test@example.com">Mail</a>')
        self.assertIn("https://example.com/profile", parser.links)
        self.assertIn("https://example.com/base/page.html", parser.links)
        self.assertFalse(any(link.startswith("mailto:") for link in parser.links))

    def test_ai_keyword_json_parser_and_prompt(self):
        words = parse_ai_keywords('{"keywords":["Kista","PAOK","Thessaloniki"]}')
        self.assertEqual(words, ["Kista", "PAOK", "Thessaloniki"])
        prompt = ai_keyword_prompt("Kista PAOK", 5)
        self.assertIn('"keywords"', prompt)
        self.assertIn("Kista PAOK", prompt)

    def test_ai_config_round_trip_and_load(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "ai.env")
            write_ai_config(
                {
                    "OPENAI_API_KEY": "openai-test-value",
                    "W0RDIT_OPENAI_MODEL": "gpt-test",
                    "IGNORED": "nope",
                },
                path,
            )
            values = read_ai_config(path)
            old_key = os.environ.pop("OPENAI_API_KEY", None)
            old_model = os.environ.pop("W0RDIT_OPENAI_MODEL", None)
            try:
                loaded = load_ai_config(path)
                self.assertIn("OPENAI_API_KEY", loaded)
                self.assertEqual(os.environ["OPENAI_API_KEY"], "openai-test-value")
                self.assertEqual(os.environ["W0RDIT_OPENAI_MODEL"], "gpt-test")
            finally:
                if old_key is not None:
                    os.environ["OPENAI_API_KEY"] = old_key
                else:
                    os.environ.pop("OPENAI_API_KEY", None)
                if old_model is not None:
                    os.environ["W0RDIT_OPENAI_MODEL"] = old_model
                else:
                    os.environ.pop("W0RDIT_OPENAI_MODEL", None)

        self.assertEqual(values["OPENAI_API_KEY"], "openai-test-value")
        self.assertNotIn("IGNORED", values)
        self.assertEqual(mask_secret("1234567890"), "1234...7890")
        self.assertEqual(ai_provider_label("openai"), "OpenAI")

    def test_huge_masks_cover_long_digit_symbol_tail(self):
        masks = generate_huge_masks(["kista"], digit_lengths=(9,), symbol_count=2)
        expected = "Kista" + "?d" * 9 + "?s?s"
        self.assertIn(expected, masks)
        self.assertGreaterEqual(estimate_mask_collection_keyspace([expected]), 10**9)

    def test_huge_masks_escape_known_question_mark_suffix(self):
        masks = generate_huge_masks(
            ["kista"],
            digit_lengths=(9,),
            case_modes=("capitalize",),
            known_digits="371046229",
            known_suffix="?!",
        )
        self.assertIn("Kista371046229??!", masks)
        self.assertEqual(escape_mask_literal("?!"), "??!")

    def test_hashcat_rules_contain_append_syntax(self):
        rules = generate_hashcat_rules(("2026",), ("!",))
        self.assertIn("$2$0$2$6", rules)
        self.assertIn("$2$0$2$6$!", rules)


if __name__ == "__main__":
    unittest.main()
