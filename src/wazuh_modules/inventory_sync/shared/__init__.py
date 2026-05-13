"""
Shared utilities for Inventory Sync QA and benchmark tools.

This package centralizes the FlatBuffers manager, the FlatBuffers generator,
and the Wazuh agent controller so that both qa/ and benchmark/ tools can
import them from a single source of truth.

Entry-point scripts should add this directory to sys.path before importing,
e.g.:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
    from flatbuffers_manager import FlatBuffersManager, parse_message
    from agent_controller import WazuhAgent
"""
