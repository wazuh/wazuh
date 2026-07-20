from helper_test.documentation_generator.types import Documentation
from helper_test.documentation_generator.exporter import *


class HTMLGenerator(IExporter):
    def __init__(self):
        self.content = []
        self.helper_name = ""

    def create_document(self, doc: Documentation):
        pass

    def save(self, output_dir: Path):
        pass
