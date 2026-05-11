# w0rd!t

w0rd!t is a friendly Python wordlist builder for authorized password recovery,
password auditing, CTFs, and training labs. It turns real hints into useful,
bounded candidate lists and exports masks for huge search spaces that should not
be written as giant text files.

Created by **Dimitris Detsirapis**.

It does not automate logins, credential stuffing, exploitation, or cracking. Use
it only on systems, accounts, URLs, and data you are explicitly authorized to
assess.

## Features

- Interactive terminal menu with tab-completed file paths.
- Hint/profile-based wordlist generation.
- Manual word entry and wordlist import.
- Focused mutation styles: numbers, symbols, capitals, mixed, quick, and wide.
- URL and file harvesting with GitHub profile support.
- Optional bounded recursive harvest with AI keyword enrichment.
- Huge-pattern `.hcmask` export for shapes like `Kista` + 9 digits + 2 symbols.
- Hashcat-style mask generation, `.hcmask` templates, and small rule exports.
- Scriptable command-line mode for repeatable workflows.

## Requirements

- Python 3.10 or newer.
- No required third-party Python packages.
- Optional AI enrichment:
  - OpenAI: `OPENAI_API_KEY`
  - Gemini: `GEMINI_API_KEY`

## Run

```bash
python3 wordit.py
```

The main menu opens immediately:

```text
w0rd!t > 1      # create from hints
w0rd!t > 4      # improve / mutate current list
w0rd!t > 5      # preview
w0rd!t > 6      # save
```

Inside the advanced menu, choices start at `1` again. Press `0` to return to
the main menu and `9` to exit.

When a prompt asks for a file path, press `Tab` to browse files and folders.
Directories are shown with a trailing `/`.

## Common Workflows

Create a focused list from hints:

```bash
python3 wordit.py --profile "alice, acme, phoenix, 2026" --mutate focused -o words.txt
```

Import an existing list and add number-based mutations:

```bash
python3 wordit.py --import-file base.txt --mutate numbers -o expanded.txt
```

Harvest one authorized URL:

```bash
python3 wordit.py --harvest-url https://example.com --i-understand -o harvested.txt
```

Generate a bounded mask:

```bash
python3 wordit.py --mask '?l?l?l?d?d' --max-candidates 50000 -o mask.txt
```

Use a custom mask charset:

```bash
python3 wordit.py --mask '?1?1?d?d' --custom1 abcxyz -o custom-mask.txt
```

Export helper files:

```bash
python3 wordit.py --profile "acme, summer, 2026" --rules-out w0rdit.rule --hcmask-out w0rdit.hcmask
```

## Mutation Styles

Use these from the menu or with `--mutate STYLE`:

- `focused`: best first try with words, capitalization, numbers, symbols, and
  `word + number/symbol + word` combinations.
- `numbers`: add digits only.
- `symbols`: add special characters only.
- `both`: add numbers and special characters.
- `caps`: capitalization variants only.
- `quick`: smaller and faster.
- `wide`: larger search space.

## Huge Patterns

Some likely passwords are too large to write as text. For example:

```text
Tester123456789?!
```

That shape is better represented as a mask:

```text
Tester?d?d?d?d?d?d?d?d?d?s?s
```

Use `Advanced options` -> `Huge password patterns` to export `.hcmask` files for
these cases. w0rd!t estimates the represented keyspace instead of trying to
create billions or trillions of candidates.

## URL Harvesting

GitHub profile URLs are harvested through GitHub's public API first, so public
profile details and repository names/descriptions are cleaner than raw page
HTML. If you enter `github.com/user` without `https://`, w0rd!t normalizes it.

If a URL cannot be fetched but contains useful path text, w0rd!t still adds
best-effort URL tokens such as names split from hyphenated profile paths.

## AI Smart Harvest

`Advanced options` -> `AI smart harvest` can crawl a small authorized scope and
optionally ask OpenAI or Gemini to extract better seed words from the harvested
text.

Use `Advanced options` -> `AI API setup` to enter an API key from the menu. Keys
are hidden while typing in a real terminal. They are session-only by default. If
you choose to save them, w0rd!t writes:

```text
~/.config/w0rdit/ai.env
```

with permissions set to `600`.

You can also configure keys manually:

```bash
export OPENAI_API_KEY="..."
export GEMINI_API_KEY="..."
```

Optional model overrides:

```bash
export W0RDIT_OPENAI_MODEL="gpt-4.1-mini"
export W0RDIT_GEMINI_MODEL="gemini-2.5-flash"
```

Without an API key, choose provider `off`; bounded recursive harvesting still
works without AI enrichment.

## Test

```bash
python3 -m py_compile wordit.py tests/test_wordit.py
python3 -m unittest
```

## Repository Notes

Generated wordlists, masks, rule files, caches, local scratch files, and AI
configuration files are ignored by `.gitignore`.

Before publishing, review any local files that are not part of the project.
This workspace currently contains ignored scratch/generated files that should not
be committed.

## License

MIT License. See [LICENSE](LICENSE).
