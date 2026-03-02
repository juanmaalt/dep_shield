from textwrap import dedent

from openai import RateLimitError, APIError, APIConnectionError

from src.scanners.models import Vulnerability, CodeUsage
from src.rag.client import openai_client
from src.rag.models import PackageInfo, SimilarCVE, ImpactAnalysis
from src.rag.store import add_cve, search_similar

_SYSTEM_PROMPT = """You are a security analyst reviewing Python dependency vulnerabilities.
Given a CVE description and import-level code evidence, determine whether
the vulnerability realistically affects this codebase.

Reasoning steps:
1. Identify the vulnerable component or behavior described in the CVE.
2. Check whether the code imports or invokes that specific component.
3. Consider the context (tests, dev tooling, production code).
4. Choose the risk level that best fits the evidence.

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


def analyze_impact(cve_info: Vulnerability, code_usages: list[CodeUsage], package: PackageInfo | None = None) -> ImpactAnalysis:
    if not code_usages:
        return ImpactAnalysis(risk_level="NONE", explanation="No usages found", recommendation="No action needed")

    code_snippets = [usage.line_content for usage in code_usages]

    pkg_prefix = f"{package} " if package else ""
    query = f"{pkg_prefix}{cve_info.summary} {cve_info.details or ''}"
    similar_cves = search_similar(query, exclude_id=cve_info.id)

    user_message = build_prompt(cve_info, code_snippets, similar_cves, pkg_prefix)
    result = call_llm(user_message)

    if result.risk_level != "UNKNOWN":
        add_cve(
            cve_info.id,
            f"{cve_info.summary}\n{cve_info.details or ''}",
            package=package.name if package else "",
            version=package.version or "" if package else "",
            risk_level=result.risk_level,
            explanation=result.explanation,
        )

    return result


def build_prompt(cve_info: Vulnerability, code_snippets: list[str], similar_cves: list[SimilarCVE] | None = None, pkg_prefix: str | None = None) -> str:
    package_line = f"\nPackage: {pkg_prefix.strip()}" if pkg_prefix else ""
    snippets_text = "\n".join(f"  - {s}" for s in code_snippets)

    similar_section = ""
    if similar_cves:
        examples = "\n".join(
            f"  - {cve.id} (similarity {1 - cve.distance:.0%}): {cve.metadata}"
            for cve in similar_cves
        )
        similar_section = f"\nSimilar CVEs previously analyzed (use as reference only):\n{examples}\n"

    return dedent(f"""
        CVE: {cve_info.id}{package_line}
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
