from abc import ABC, abstractmethod
from pathlib import Path

class ScannerPlugin(ABC):
    def __init__(self, workdir: Path):
        self.workdir = workdir

    @abstractmethod
    def run(self, targets_path: Path, options: dict):
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_output_path: Path):
        raise NotImplementedError
