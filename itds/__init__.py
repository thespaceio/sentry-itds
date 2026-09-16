"""Sentry — an insider threat detection system.

Behavioural monitoring that accumulates risk per entity rather than firing an
alert per event, with explainability and privacy controls built in rather than
bolted on.
"""

__version__ = "0.1.0"

from .config import DEFAULT_CONFIG, Config
from .pipeline import Pipeline
from .schema import Category, Event, Identity, Sensitivity

__all__ = [
    "Config",
    "DEFAULT_CONFIG",
    "Pipeline",
    "Event",
    "Identity",
    "Category",
    "Sensitivity",
    "__version__",
]
