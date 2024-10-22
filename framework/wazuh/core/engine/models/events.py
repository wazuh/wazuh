from dataclasses import dataclass


@dataclass
class WazuhLocation:
    """Stateless events send location data model."""
    queue: int
    location: str


@dataclass
class Event:
    """Engine event data model."""
    original: str


@dataclass
class StatelessEvent:
    """Stateless event data model."""
    wazuh: WazuhLocation
    event: Event
