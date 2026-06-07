"""Configuration management for Excalibur using Pydantic."""

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExcaliburConfig(BaseSettings):
    """Main configuration for Excalibur."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM Configuration
    llm_provider: Literal["claude", "gemini"] = Field(
        default="claude", description="LLM backend provider"
    )

    llm_model: str = Field(
        default="claude-sonnet-4-5-20250929", description="Provider model to use for the agent"
    )

    llm_api_key: str | None = Field(
        default=None, description="Optional API key (Claude Code manages its own config)"
    )

    llm_api_base: str | None = Field(default=None, description="Optional custom API base URL")
    gemini_tool_timeout: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum seconds for a Gemini shell tool call",
    )
    gemini_api_mode: Literal["developer", "vertex"] = Field(
        default="developer",
        description="Gemini Developer API or Vertex AI endpoint",
    )
    google_cloud_project: str | None = Field(
        default=None,
        description="Google Cloud project for Vertex AI ADC authentication",
    )
    google_cloud_location: str = Field(
        default="global",
        description="Google Cloud location for Vertex AI",
    )

    # Agent Configuration
    max_iterations: int = Field(default=300, description="Maximum iterations for the agent")

    working_directory: Path = Field(
        default_factory=lambda: Path.cwd() / "workspace"
        if Path.cwd().name != "workspace"
        else Path.cwd(),
        description="Working directory for agent operations",
    )

    # Target Configuration
    target: str = Field(
        ...,  # Required
        description="Target for penetration testing (URL, IP, domain, or path)",
    )

    custom_instruction: str | None = Field(
        default=None, description="Optional custom instructions for the agent"
    )

    # Interface Configuration
    interface_mode: Literal["tui", "cli"] = Field(
        default="tui", description="Interface mode: TUI (interactive) or CLI (headless)"
    )

    verbose: bool = Field(default=True, description="Enable verbose output")

    # Permission Mode
    permission_mode: Literal["ask", "bypassPermissions"] = Field(
        default="bypassPermissions", description="Permission mode for Claude Code SDK"
    )

    # TDA Weights
    tda_weight_horizon: float = Field(default=0.3, description="TDA horizon weight")
    tda_weight_evidence: float = Field(default=0.3, description="TDA evidence weight")
    tda_weight_context: float = Field(default=0.2, description="TDA context load weight")
    tda_weight_success: float = Field(default=0.2, description="TDA success rate weight")

    # EGATS Thresholds
    egats_explore_threshold: float = Field(
        default=0.6, description="TDI above this -> reconnaissance (BFS)"
    )
    egats_exploit_threshold: float = Field(
        default=0.3, description="TDI below this -> exploitation (DFS)"
    )
    egats_prune_threshold: float = Field(
        default=0.8, description="TDI above this + min attempts -> prune branch"
    )
    egats_min_prune_attempts: int = Field(
        default=3, description="Minimum visits before pruning a branch"
    )

    # UCB Parameters
    egats_ucb_exploration_constant: float = Field(
        default=1.414, description="UCB exploration constant (sqrt(2))"
    )
    egats_ucb_difficulty_penalty: float = Field(
        default=0.5, description="UCB difficulty penalty weight"
    )
    egats_backprop_alpha: float = Field(default=0.7, description="Backpropagation smoothing factor")

    # Memory / Context
    context_ideal_threshold: float = Field(
        default=0.4, description="Context load threshold for moderate compression"
    )
    context_aggressive_threshold: float = Field(
        default=0.7, description="Context load threshold for aggressive compression"
    )
    state_store_path: str = Field(
        default=":memory:", description="SQLite path for state store (:memory: for in-memory)"
    )

    # Budget
    max_budget: int = Field(default=300, description="Maximum EGATS iteration budget")

    def __init__(self, **data: Any) -> None:
        """Initialize configuration."""
        super().__init__(**data)

        # Create working directory if it doesn't exist
        # Ignore permission errors if directory already exists
        try:
            self.working_directory.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # Directory already exists or we don't have permission to create it
            # This is fine if the directory is already available
            if not self.working_directory.exists():
                raise

    @model_validator(mode="after")
    def select_provider_default_model(self) -> "ExcaliburConfig":
        """Use a compatible default model when Gemini is selected."""
        if self.llm_provider == "gemini" and self.llm_model == "claude-sonnet-4-5-20250929":
            self.llm_model = "gemini-2.5-flash"
        return self

    @property
    def system_prompt_path(self) -> Path:
        """Get path to system prompt file."""
        return Path(__file__).parent.parent / "prompts" / "pentesting.py"

    @property
    def egats_config(self) -> dict[str, object]:
        """Build EGATS planner configuration dict."""
        return {
            "exploration_constant": self.egats_ucb_exploration_constant,
            "difficulty_penalty": self.egats_ucb_difficulty_penalty,
            "backprop_alpha": self.egats_backprop_alpha,
            "prune_threshold": self.egats_prune_threshold,
            "min_prune_attempts": self.egats_min_prune_attempts,
            "bfs_threshold": self.egats_explore_threshold,
            "dfs_threshold": self.egats_exploit_threshold,
            "tda_weights": {
                "horizon": self.tda_weight_horizon,
                "evidence": self.tda_weight_evidence,
                "context": self.tda_weight_context,
                "success": self.tda_weight_success,
            },
        }

    @classmethod
    def from_env(cls, **overrides: object) -> "ExcaliburConfig":
        """Create config from environment variables with optional overrides."""
        return cls(**overrides)


def load_config(**overrides: object) -> ExcaliburConfig:
    """
    Load configuration from environment with optional overrides.

    Args:
        **overrides: Keyword arguments to override config values

    Returns:
        ExcaliburConfig instance

    Example:
        >>> config = load_config(target="example.com", verbose=True)
    """
    # Create config with overrides
    # Note: API key is optional - Claude Code manages its own configuration
    return ExcaliburConfig.from_env(**overrides)
