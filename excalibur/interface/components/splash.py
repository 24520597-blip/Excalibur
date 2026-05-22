"""Splash screen component with ASCII banner for Excalibur TUI."""

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from rich.align import Align
from rich.console import Group
from rich.style import Style
from rich.text import Text
from textual.widgets import Static

if TYPE_CHECKING:
    from textual.timer import Timer


class SplashScreen(Static):
    """Animated splash screen with ASCII banner and loading indicator."""

    # Color scheme - modern indigo/purple
    PRIMARY_COLOR = "#6366f1"
    SECONDARY_COLOR = "#8b5cf6"

    # ASCII Art Banner - Clean and modern design
    BANNER = """
    ███████╗██╗  ██╗ ██████╗ █████╗ ██╗     ██╗██████╗ ██╗   ██╗██████╗
    ██╔════╝╚██╗██╔╝██╔════╝██╔══██╗██║     ██║██╔══██╗██║   ██║██╔══██╗
    █████╗   ╚███╔╝ ██║     ███████║██║     ██║██████╔╝██║   ██║██████╔╝
    ██╔══╝   ██╔██╗ ██║     ██╔══██║██║     ██║██╔══██╗██║   ██║██╔══██╗
    ███████╗██╔╝ ██╗╚██████╗██║  ██║███████╗██║██████╔╝╚██████╔╝██║  ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize splash screen."""
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer: Timer | None = None
        self._panel_static: Static | None = None
        self._version = "2.0.0"

    def compose(self) -> Iterator[Static]:
        """Create the splash screen content."""
        self._animation_step = 0
        loading_text = self._build_loading_text(self._animation_step)
        content = self._build_content(loading_text)

        panel_static = Static(content, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        """Start animation when mounted."""
        self._animation_timer = self.set_interval(0.4, self._animate_loading)

    def on_unmount(self) -> None:
        """Stop animation when unmounted."""
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_loading(self) -> None:
        """Animate the loading indicator."""
        if not self._panel_static:
            return

        self._animation_step = (self._animation_step + 1) % 4
        loading_text = self._build_loading_text(self._animation_step)
        content = self._build_content(loading_text)
        self._panel_static.update(content)

    def _build_content(self, loading_text: Text) -> Group:
        """Build the complete splash screen content."""
        # Banner with gradient effect
        banner_text = Text(self.BANNER.strip("\n"), justify="center")
        banner_text.stylize(self.PRIMARY_COLOR)

        # Title line
        title_text = Text()
        title_text.append("AI-Powered ", style=Style(color="#a3a3a3"))
        title_text.append("Penetration Testing", style=Style(color=self.PRIMARY_COLOR, bold=True))
        title_text.append(" Assistant", style=Style(color="#a3a3a3"))

        # Version
        version_text = Text(f"v{self._version}", style=Style(color="#525252", dim=True))

        # Tagline
        tagline_text = Text(
            "AI Security Agent", style=Style(color=self.SECONDARY_COLOR, italic=True)
        )

        return Group(
            Align.center(banner_text),
            Align.center(Text(" ")),
            Align.center(title_text),
            Align.center(version_text),
            Align.center(Text(" ")),
            Align.center(tagline_text),
            Align.center(Text(" ")),
            Align.center(Text(" ")),
            Align.center(loading_text),
        )

    def _build_loading_text(self, phase: int) -> Text:
        """Build animated loading text with dots."""
        dots = "." * phase
        spaces = " " * (3 - phase)

        text = Text()
        text.append("Initializing", style=Style(color=self.PRIMARY_COLOR, bold=True))
        text.append(dots, style=Style(color=self.SECONDARY_COLOR))
        text.append(spaces)  # Keep consistent width

        return text
