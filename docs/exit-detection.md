# Exit Detection

Exit detection adds a compact section to the bottom of the tooltip:

```text
---- Exit Check ----
Google	->	US GGL
YouTube	->	JP GGL
OpenAI	->	US CF
Claude	->	US CF
GitHub	->	US GH
Netflix	->	JP NFLX
```

- Disabled by default. Enable it in plugin settings with `enable_exit_detection`.
- Results use two-letter country codes and short network tags only.
- No emoji flags and no full country names are shown.
- Rows use tab-separated columns to keep the arrow and result columns aligned in the Windows tooltip.
- Failed probes show `-- ----`; pending probes show `-- WAIT`.
- Results are cached for 10 minutes. Manual external-IP refresh and proxy-window changes force a new exit-detection refresh.
