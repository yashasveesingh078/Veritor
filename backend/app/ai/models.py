"""Data models for AI-driven code investigation.

AI models interpret and explain deterministic evidence. They never decide risk scores,
alter severity levels, or invent findings. Package contents are untrusted data.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AIInvestigationStatus(StrEnum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class FindingExplanation(BaseModel):
    """An AI-generated, schema-validated explanation for a deterministic finding."""

    model_config = ConfigDict(frozen=True)

    finding_ref: str = Field(description="Identifier of the deterministic finding or rule.")
    path: str = Field(description="Path to the file containing the finding.")
    line: int | None = Field(default=None, description="1-based line number if applicable.")
    explanation: str = Field(description="Clear explanation of what the flagged code does.")
    evidence_reference: str = Field(
        description="Explicit reference or quote of the deterministic evidence."
    )
    behavior_analysis: str = Field(
        description="Analysis of the observed code behavior in the context of the package."
    )
    uncertainty: str = Field(
        description="Explicit evaluation of certainty, limitations, or unverified aspects."
    )
    recommendation: str = Field(
        description="Actionable guidance for reviewers regarding this specific finding."
    )


class AIInvestigationResult(BaseModel):
    """The complete result of an AI investigation."""

    model_config = ConfigDict(frozen=True)

    status: AIInvestigationStatus
    model: str = Field(description="Model name used for investigation (e.g. qwen2.5-coder:7b).")
    summary: str = Field(description="High-level narrative summary of findings.")
    explanations: tuple[FindingExplanation, ...] = Field(
        default=(), description="Per-finding validated structured explanations."
    )
    overall_uncertainty: str = Field(
        default="Deterministic findings are conclusive; no AI interpretation needed.",
        description="Overall assessment of uncertainty, gaps, or limitations.",
    )
    recommendations: tuple[str, ...] = Field(
        default=(), description="General actionable recommendations for the package release."
    )
    error: str | None = Field(
        default=None, description="Error message if Ollama or inference was unavailable/failed."
    )
