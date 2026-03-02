from typing import Literal

from openai import RateLimitError, APIError, APIConnectionError
from pydantic import BaseModel
from textwrap import dedent

from src.scanners.osv import Vulnerability
from src.scanners.code_scanner import CodeUsage
from src.rag.client import openai_client
from src.rag.store import SimilarCVE, add_cve, search_similar

_SYSTEM_PROMPT = """You are a security analyst reviewing Python dependency vulnerabilities.
Given a CVE description and import-level code evidence, determine whether
the vulnerability realistically affects this codebase.
Be conservative: only escalate risk when the evidence clearly supports it.
In your recommendation, specify the lowest fixed version and note whether
upgrading is a drop-in update or requires breaking code changes.

Risk level definitions:
- HIGH    : Imports directly reference the vulnerable function, class, or
            feature named in the CVE, or usage clearly exercises the attack surface.
- MEDIUM  : The package is imported but there is no clear evidence the vulnerable
            feature is exercised.
- LOW     : The package is imported only in tests, optional dependencies, or dev
            tooling where the vulnerability is unlikely to trigger in production.
- NONE    : Imports only use utility/non-vulnerable submodules, or the CVE
            requires conditions not plausible in this codebase.
- UNKNOWN : Insufficient information to assess impact (missing CVE details or
            ambiguous code evidence)."""


class ImpactAnalysis(BaseModel):
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    explanation: str
    recommendation: str


def analyze_impact(cve_info: Vulnerability, code_usages: list[CodeUsage]) -> ImpactAnalysis:
    if not code_usages:
        return ImpactAnalysis(risk_level="NONE", explanation="No usages found", recommendation="No action needed")

    code_snippets = [usage.line_content for usage in code_usages]

    query = f"{cve_info.summary} {cve_info.details or ''}"
    similar_cves = search_similar(query)

    user_message = build_prompt(cve_info, code_snippets, similar_cves)
    result = call_llm(user_message)

    add_cve(
        cve_info.id,
        f"{cve_info.summary}\n{cve_info.details or ''}",
        f"{result.risk_level}: {result.explanation}",
    )

    return result


def build_prompt(cve_info: Vulnerability, code_snippets: list[str], similar_cves: list[SimilarCVE] | None = None) -> str:
    snippets_text = "\n".join(f"  - {s}" for s in code_snippets)

    similar_section = ""
    if similar_cves:
        examples = "\n".join(f"  - {c.id}: {c.metadata}" for c in similar_cves)
        similar_section = f"\nSimilar CVEs previously analyzed (use as reference only):\n{examples}\n"

    return dedent(f"""
        CVE: {cve_info.id}
        OSV severity: {cve_info.severity or "UNKNOWN"}
        Summary: {cve_info.summary}
        Details: {cve_info.details}
        {similar_section}
        Code usage (import statements only):
        {snippets_text}
    """).strip()


def call_llm(user_message: str) -> ImpactAnalysis:
    try:
        response = openai_client.beta.chat.completions.parse(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            response_format=ImpactAnalysis,
        )
        return response.choices[0].message.parsed
    except RateLimitError:
        return ImpactAnalysis(
            risk_level="UNKNOWN",
            explanation="Rate limit exceeded. Could not perform the analysis.",
            recommendation="Try again later or check the API quota."
        )
    except (APIError, APIConnectionError) as e:
        return ImpactAnalysis(
            risk_level="UNKNOWN",
            explanation=f"API error: {str(e)}",
            recommendation="Check your API key and connection."
        )
