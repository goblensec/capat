"""capat - measure how well an image CAPTCHA resists automation.

Built for authorized security testing and for the argument that follows it:
image recognition has stopped being a meaningful barrier, so a CAPTCHA should
not be counted as the control that prevents automated login attempts.
"""

from capat.core.config import Config
from capat.core.engine import Engine
from capat.core.matching import Matcher, Outcome, SuccessCriteria
from capat.core.profile import LoginProfile
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.core.template import Extractor

__version__ = "0.1.0"

__all__ = [
    "Config",
    "Engine",
    "Finding",
    "Extractor",
    "LoginProfile",
    "Matcher",
    "Outcome",
    "Severity",
    "SuccessCriteria",
    "Target",
    "__version__",
]
