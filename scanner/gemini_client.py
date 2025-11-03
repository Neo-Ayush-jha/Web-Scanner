# scanner/gemini_client.py
import os
from typing import Optional
try:
    from google import genai   # official sample import from docs
except Exception:
    genai = None

GEMINI_MODEL = "gemini-2.5-flash"   # choose model as per docs / quota

def _init_client(api_key: Optional[str] = None):
    if genai is None:
        raise ImportError("google-genai library not installed.")
    if api_key:
        return genai.Client(api_key=api_key)
    # The client picks up GEMINI_API_KEY env var by default (per docs)
    return genai.Client()

def build_port_prompt(port: int, service: str = "", state: str = "") -> str:
    # A structured prompt so Gemini returns detail in a predictable form.
    return (
        f"Provide a detailed, technical description of TCP/UDP port {port}.\n\n"
        f"Include these sections (use headings):\n"
        f"1) Short summary (1-2 lines)\n"
        f"2) Typical services & protocols that run on this port\n"
        f"3) Common banners/indicators found in network scans\n"
        f"4) Typical risks & known vulnerabilities (if publicly known)\n"
        f"5) Mitigations and best practices\n"
        f"6) Example commands to test or safely probe (nmap/curl)\n"
        f"7) References (list up to 3 short references or keywords)\n\n"
        f"Ports state: {state or 'unknown'}. Service name: {service or 'unknown'}.\n"
        f"Return the answer as plain text."
    )

def fetch_port_description_from_gemini(port: int, service: str = "", state: str = "", api_key: Optional[str] = None) -> str:
    """
    Calls Gemini to create a detailed description. Caller should handle exceptions.
    """
    client = _init_client(api_key)
    prompt = build_port_prompt(port, service, state)
    # generate_content usage from quickstart
    resp = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    # Some SDK responses have .text or .result; adapt per SDK version
    # Official examples show `response.text`
    text = getattr(resp, "text", None)
    if text is None:
        # try fallback
        text = str(resp)
    return text
