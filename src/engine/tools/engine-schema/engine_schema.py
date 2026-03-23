#!/usr/bin/env python3

import sys
import os
from pathlib import Path

script_dir = Path(__file__).parent
src_dir = script_dir / "src"
sys.path.insert(0, str(src_dir))

from engine_schema.__main__ import main

if __name__ == '__main__':
    sys.exit(main())