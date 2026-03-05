# dep_shield

A Python dependency vulnerability scanner that detects known CVEs in your project's dependencies using the OSV database and provides AI-powered impact analysis to assess how each vulnerability affects your specific codebase.

---

## How does it work?

```
requirements.txt  ↘
                   dependency list → OSV API → vulnerabilities
pyproject.toml    ↗                                   ↓
                                        Python files → import scanner → code usage
                                                      ↓
                                          (--analyze only, skipped if not imported)
                                                      ↓
                                          LLM impact analysis
                                                      ↓
                                    ChromaDB (RAG vector store)
```

1. Discover and parse `requirements.txt` and/or `pyproject.toml` (PEP 621 and Poetry formats) to extract package names and versions; duplicates across files are deduplicated
2. Query the OSV API for each dependency to find known CVEs
3. For each vulnerable dependency, scan all `.py` files to detect import statements and usage locations
4. If `--analyze` is set and the package is imported, retrieve similar past CVEs from ChromaDB and call GPT-4o-mini with CVE details + import context; if the package is not imported anywhere the LLM call is skipped and risk is reported as `NONE`
5. Display results with severity color-coding and optional LLM recommendations
6. Persist analyzed CVEs to ChromaDB for future similarity lookups
7. Exit with code `1` if any vulnerabilities are found, `0` if the project is clean

### Ignored directories

The import scanner skips `.venv`, `venv`, `__pycache__`, `.git`, `node_modules`, `.eggs`, `build`, and `dist`.

### Risk levels

| Level | Meaning |
|---|---|
| `HIGH` | Imports directly reference the vulnerable function or feature named in the CVE |
| `MEDIUM` | Package is imported but no clear evidence the vulnerable feature is exercised |
| `LOW` | Package is only imported in tests, dev tooling, or optional dependencies |
| `NONE` | Package is not imported, or CVE conditions are not plausible in this codebase |
| `UNKNOWN` | API error or rate limit prevented analysis |

---

## Installation Requirements

- Python 3.12 or higher
- The `uv` package manager
- An OpenAI API key (required for `--analyze` mode)

```bash
git clone <repo-url>
cd dep_shield
uv sync
```

## Configuration

Set the following environment variable in a `.env` file at the project root:

```
OPENAI_API_KEY=sk-...
```

| Setting | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | *(required for `--analyze`)* | OpenAI API key |
| Embedding model | `text-embedding-3-small` | OpenAI model used for CVE embeddings |
| Analysis model | `gpt-4o-mini` | OpenAI model used for impact analysis |
| Vector store path | `~/.dep_shield/chroma/` | Local ChromaDB persistent storage |
| Similarity threshold | `0.35` | Minimum cosine distance to retrieve similar past CVEs |
| Top-k similar CVEs | `3` | Number of past analyses used as context |

## Usage

```bash
# Scan a project directory (auto-detects requirements.txt and/or pyproject.toml)
uv run dep_shield <path>

# Scan with AI-powered impact analysis
uv run dep_shield <path> --analyze
```

**Examples:**

```bash
uv run dep_shield .
uv run dep_shield ./requirements.txt --analyze
uv run dep_shield ./pyproject.toml --analyze
uv run dep_shield /path/to/project -a
```

---

## Project Structure

```
src/
├── cli.py                  # Typer CLI entry point
├── parsers/
│   ├── requirements.py     # requirements.txt parser
│   └── pyproject.py        # pyproject.toml parser (PEP 621 + Poetry)
├── scanners/
│   ├── models.py           # Vulnerability and CodeUsage dataclasses
│   ├── osv.py              # OSV API client (async httpx)
│   └── code_scanner.py     # Python import scanner
└── rag/
    ├── analyzer.py         # LLM-based impact analysis
    ├── client.py           # OpenAI client initialization
    ├── embeddings.py       # Embedding generation
    ├── models.py           # Pydantic models (ImpactAnalysis, SimilarCVE)
    └── store.py            # ChromaDB store management
```

---

## Security Notes

* The `.env` file is excluded from version control via `.gitignore`. Never commit your `OPENAI_API_KEY` directly in source files.
* Only import statements are shared with the LLM, not your business logic. The model sees lines like `import requests` or `from flask import Flask`, never the body of your functions.
