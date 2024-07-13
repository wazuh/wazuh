from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from .types import Documentation


class ExporterType(Enum):
    PDF = 1,
    HTML = 2,
    MARK_DOWN = 3


def convert_str_to_exporter_type(type_: str):
    if type_ == "pdf":
        return ExporterType.PDF
    elif type_ == "html":
        return ExporterType.HTML
    elif type_ == "mark_down":
        return ExporterType.MARK_DOWN
    else:
        raise ValueError(f"Exporter type {type_} does not exist")


def convert_exporter_type_to_str(exporter_type: ExporterType):
    if exporter_type == convert_str_to_exporter_type("pdf"):
        return "pdf"
    elif exporter_type == convert_str_to_exporter_type("pdf"):
        return "html"
    elif exporter_type == convert_str_to_exporter_type("html"):
        return "mark_down"
    else:
        raise ValueError(f"Exporter type does not exist")


class IExporter(ABC):
    @abstractmethod
    def create_document(self, doc: Documentation):
        pass

    @abstractmethod
    def save(self, output_dir: Path):
        pass
