# Ground truth fixtures — program_fetcher benchmark

Each file here is a **frozen, hand-verified** copy of a program page's verbatim
sections (in-scope assets, out-of-scope, submission rules, severity table).
Used by `program_fetcher_bench.py` to compute verbatim-accuracy ratios
against both the `main` path (jina+regex) and the `dev` path
(`tools.program_fetcher`).

## Format

Ground truth files are single markdown documents with these headings exactly:

```markdown
# <Program Name>

## In Scope
<verbatim asset list from the live page>

## Out of Scope
<verbatim OOS list from the live page>

## Rules
<verbatim rules text from the live page>

## Rewards
<verbatim severity/reward table from the live page>

## Known Issues
<verbatim known issues, or "None documented">
```

The benchmark uses `difflib.SequenceMatcher.find_longest_match` to score each
section against the same-named section in the fetched output. Ratio = longest
common substring length ÷ ground truth length.

## Adding a new ground truth

1. Pick a URL from `bench_urls.json`.
2. Open the live program page in a browser.
3. Copy each verbatim section byte-for-byte into a new file `ground_truth/<id>.md`.
4. Set `"ground_truth": "<id>.md"` on the matching entry in `bench_urls.json`.
5. Commit both together. Treat ground truth as frozen — only regenerate when
   the live page materially changes (note the date in a `<!-- frozen: YYYY-MM-DD -->`
   comment at the top of the file).

## Intentionally empty by default

No ground truth files are committed initially. The benchmark script handles
missing ground truth gracefully: `verbatim_accuracy` is reported as 0.0 and
the global accuracy gate is effectively skipped. Add ground truth files as
part of the merge PR — one per high-leverage platform is enough to make the
gate meaningful.
