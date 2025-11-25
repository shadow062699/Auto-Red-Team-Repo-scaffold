# ai_explainer.py — small wrapper that accepts a Finding and returns a friendly explanation.
# This file intentionally does not include any API keys. Replace with your preferred LLM client.


def explain_finding(finding: dict) -> dict:
# Placeholder: produce an expanded explanation
# In real use, call your LLM (OpenAI, local LLM) with a small prompt that includes:
# - the finding short & detail
# - severity
# - ask for 2-3 remediation steps (code snippets when possible)
explanation = {
"explanation":
