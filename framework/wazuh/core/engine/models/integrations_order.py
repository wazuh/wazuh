from dataclasses import dataclass
from typing import List

@dataclass
class IntegrationInfo:
    id: str
    name: str

@dataclass
class IntegrationsOrder:
    order: List[IntegrationInfo]
