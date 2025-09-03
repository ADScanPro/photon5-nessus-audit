# Contributing

Thanks for your interest in contributing! PRs and issues are welcome.

- Fork the repo and create a feature branch.
- Follow existing style: keep audit items with `# Source: PHTN-50-xxxxxx.rb` comments.
- Only add checks present in the upstream `.rb` controls for traceability.
- Update README mapping and the unmapped list when adding/removing items.
- Use MIT license for contributions.

## Development tips
- Validate regexes carefully; prefer anchors and minimal groups to reduce false positives.
- Keep severity aligned with the original control.
- Test audits on a Photon OS 5 host with SSH sudo before submitting.
