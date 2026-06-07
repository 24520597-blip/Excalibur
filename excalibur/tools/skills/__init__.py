"""Pre-built skill definitions for Excalibur.

Each module defines Skill instances that compose multiple tools into
reusable penetration testing workflows.
"""

from excalibur.tools.skill import Skill
from excalibur.tools.skills.ad_skills import get_ad_skills
from excalibur.tools.skills.pivot_skills import get_pivot_skills
from excalibur.tools.skills.privesc_skills import get_privesc_skills
from excalibur.tools.skills.recon_skills import get_recon_skills
from excalibur.tools.skills.web_skills import get_web_skills

__all__ = [
    "get_ad_skills",
    "get_pivot_skills",
    "get_privesc_skills",
    "get_recon_skills",
    "get_web_skills",
]


def get_all_skills() -> list[Skill]:
    """Return every built-in skill from all categories."""
    skills: list[Skill] = []
    skills.extend(get_recon_skills())
    skills.extend(get_web_skills())
    skills.extend(get_privesc_skills())
    skills.extend(get_ad_skills())
    skills.extend(get_pivot_skills())
    return skills
