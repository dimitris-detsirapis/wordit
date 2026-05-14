# w0rd!t

Current version: **1.2.0**

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
- Tool-ready typed generators for password bases, subdomains, web paths, and
  cloud resource names.
- Per-type validation so generated candidates match their target tools.
- URL and file harvesting with GitHub profile support.
- Optional bounded recursive harvest with AI keyword enrichment.
- Optional AI typed generation with dry-run prompt previews.
- Batch seed-file processing for typed generation.
- Huge-pattern `.hcmask` export for shapes like `Tester` + 9 digits + 2 symbols.
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

Generate tool-ready typed lists:

```bash
python3 wordit.py --type password-base --add "alice acme phoenix" -o password_base.txt
python3 wordit.py --type subdomain --add "acme payments aws" -o subdomains.txt
python3 wordit.py --type directory --add "wordpress acme php apache" -o paths.txt
python3 wordit.py --type cloud-resource --add "acme aws payments prod" -o cloud.txt
```

Preview an AI generation prompt without spending an API call:

```bash
python3 wordit.py --type subdomain --add "acme fintech aws" --ai-generate --dry-run --max-candidates 50
```

Generate typed candidates from a seed file:

```bash
python3 wordit.py --type subdomain --batch-file seeds.txt --batch-size 5 --max-candidates 500 -o batch_subdomains.txt
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

## Typed Wordlists

Use `--type TYPE` from the command line or `typegen` inside the interactive
shell. Supported types:

- `password-base`: alphanumeric base words for Hashcat rules and hybrid attacks.
- `subdomain`: lowercase DNS labels for tools like Gobuster and ffuf.
- `directory`: relative URL paths/files for ffuf, wfuzz, Gobuster, and similar tools.
- `cloud-resource`: realistic bucket/storage/resource-name candidates.

Typed generation can run locally with no dependencies, or with AI:

```bash
python3 wordit.py --type cloud-resource --add "acme aws backup data" --ai-generate -o cloud.txt
```

Use `--dry-run` with `--ai-generate` to inspect the exact prompt before any API
call. Use `--batch-file` when each line contains a target, product, project, or
seed set that should be processed in batches.

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

## AI Features

`Advanced options` -> `AI smart harvest` can crawl a small authorized scope and
optionally ask OpenAI or Gemini to extract better seed words from the harvested
text.

When AI enrichment returns keywords, w0rd!t uses that filtered keyword set plus
URL hints instead of dumping every raw page token into the session. If AI is off,
unconfigured, or returns no usable keywords, it falls back to raw harvested words.

AI providers receive the text w0rd!t harvested; they do not make blocked pages
scrapeable. Sites such as LinkedIn may return anti-bot responses like HTTP 999,
so use an exported profile, copied profile text, or another authorized public
source when you need richer profile-specific seeds.

Typed AI generation uses the same API setup:

```bash
python3 wordit.py --type directory --add "django acme nginx" --ai-generate --ai-provider openai -o ai_paths.txt
```

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

## License

MIT License. See [LICENSE](LICENSE).
