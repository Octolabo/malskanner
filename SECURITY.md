# Security Policy

malskanner is a security tool, so bypasses matter as much as features.

## Reporting a vulnerability

If you find a payload malskanner **misses** (a false negative / evasion), a way to
make the scanner itself misbehave, or a false positive on a mainstream repo, please
report it:

- Open a private [GitHub Security Advisory](https://github.com/octolabo/malskanner/security/advisories/new), or
- Contact the maintainer via the repository profile.

Please include a **minimal reproducing file**. We aim to acknowledge within a few days.

## Scope

- **In scope:** detection bypasses/evasions, crashes or denial-of-service on crafted
  input, any way to prompt-inject the scanner, and false positives on real-world repos.
- **Out of scope:** payloads fetched **at runtime** (a documented limitation — pair
  malskanner with sandboxing), and full malware/dependency analysis (use dedicated
  tools alongside it).

## Responsible use

malskanner is a **defensive** tool. The bundled fixtures contain neutered example
payloads for testing only.
