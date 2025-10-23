# cloudMonkey

Cloud is not safe...

cloudMonkey is a Python toolkit for cloud reconnaissance and security assessment. It offers three scanning models so you can pick the right trade‑off between speed and depth:

- mini — fast, lightweight runs suitable for development and testing
- normal — balanced depth for CTFs, labs, and demos
- pro — comprehensive depth scanning for real assessments and research

Note: In some places you may see the model spelled as "noraml". In this README, "normal" is used; if the code or CLI currently expects "noraml", use that value instead.

## Why three models?

Different tasks need different signal-to-noise and runtime characteristics:

- mini
  - Goal: sanity checks, developer workflows, unit/integration tests
  - Pros: very fast, minimal dependencies, low cost
  - Cons: limited coverage, coarse heuristics
- normal
  - Goal: CTFs and training where you want meaningful findings without long runtimes
  - Pros: good balance of depth and speed
  - Cons: may skip some expensive or niche paths
- pro
  - Goal: thorough assessments and deep-dive research
  - Pros: maximum coverage, exhaustive enumeration, layered heuristics
  - Cons: slower, more resource-intensive

## Features (high level)

- Multi-step cloud reconnaissance with adjustable depth by model
- Modular enumeration and detection phases designed to be composable
- Sensible defaults for each model profile
- Deterministic behavior for testability in mini mode
- Extensible architecture for adding new checks and providers

## Getting started

Prerequisites:
- Python 3.10+ recommended
- A virtual environment (venv) is recommended

Install:

```bash
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
```

If the project uses a different dependency manager (e.g., Poetry, PDM, Hatch), adapt the steps accordingly.


## Model profiles

- mini
  - Depth: low
  - Concurrency: conservative
  - Timeouts: short
  - Use cases: CI sanity checks, local dev loops, unit tests

- normal
  - Depth: medium
  - Concurrency: balanced
  - Timeouts: standard
  - Use cases: CTFs, workshops, demonstrations, exploratory runs

- pro
  - Depth: high
  - Concurrency: tuned for throughput
  - Timeouts: generous
  - Use cases: comprehensive audits, methodical research, large targets

## Configuration

Typical configuration approaches:
- Command-line flags to override model defaults
- Environment variables for credentials and provider context
- Optional YAML/TOML file to persist preferences

Examples of environment variables often used in cloud tooling (only set what you need, and only for assets you own):
- AWS: AWS_PROFILE, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION
- GCP: GOOGLE_APPLICATION_CREDENTIALS
- Azure: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID

Refer to the project’s code or CLI help for the exact configuration supported.

## Output

Outputs typically include:
- Summary of discovered assets and potential misconfigurations
- Artifact files (e.g., JSON) for downstream analysis
- Optional verbose logs per phase

Use --output to write results to disk if supported.

## Development

Set up a dev environment:
```bash
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```



Suggested commit and PR guidelines:
- Keep changes small and focused
- Add or update tests for new behavior
- Document flags and config changes
- For model changes, update the profile documentation above

## Roadmap ideas

- Provider-specific modules with pluggable discovery steps
- Expanded rule sets for misconfiguration detection
- Caching and resumable scans for large targets
- Rich output formats and export to common platforms
- Benchmarks for all three models

## Responsible and legal use

Only scan systems, accounts, and data that you own or have explicit permission to assess. Follow all applicable laws, terms of service, and organizational policies. The authors and contributors are not responsible for misuse or damages arising from the use of this tool.


## Acknowledgments

Thanks to the cloud security and CTF communities whose research and challenges inspire tooling like cloudMonkey.


