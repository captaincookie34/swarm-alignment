"""Traceable agent harness."""
import os

# Pydantic AI prints a promotional banner on first run; keep CLI output clean.
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")
