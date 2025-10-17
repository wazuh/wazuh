#!/usr/bin/env python3
"""
FlatBuffers Manager for Inventory Sync Testing
This module handles the import and generation of FlatBuffers classes.
"""
import os
import sys
import importlib
from pathlib import Path
from typing import Optional, Any

class FlatBuffersManager:
    """Manages FlatBuffers classes for inventory sync testing."""

    def __init__(self):
        self.schema = None
        self.generated_module = None
        self.fallback_module = None
        self._load_modules()

    def _load_modules(self):
        """Load FlatBuffers modules, generating them if necessary."""
        # First, try to generate the classes
        try:
            from generate_flatbuffers import main as generate_main
            result = generate_main()

            if result is True:
                # Generated classes successfully
                self._load_generated_classes()
            else:
                # Generation failed
                raise RuntimeError("Failed to generate FlatBuffers classes")

        except ImportError:
            # generate_flatbuffers not available, try to load existing classes
            self._load_generated_classes()

    def _load_generated_classes(self):
        """Load the generated FlatBuffers classes."""
        try:
            # Add generated directory to path
            generated_dir = Path(__file__).parent / "generated"
            if generated_dir.exists():
                sys.path.insert(0, str(generated_dir))

            # Import the individual generated modules
            import Wazuh.SyncSchema.Mode as ModeModule
            import Wazuh.SyncSchema.Operation as OperationModule
            import Wazuh.SyncSchema.Status as StatusModule
            import Wazuh.SyncSchema.MessageType as MessageTypeModule
            import Wazuh.SyncSchema.DataValue as DataModule
            import Wazuh.SyncSchema.Start as StartModule
            import Wazuh.SyncSchema.StartAck as StartAckModule
            import Wazuh.SyncSchema.End as EndModule
            import Wazuh.SyncSchema.EndAck as EndAckModule
            import Wazuh.SyncSchema.Pair as PairModule
            import Wazuh.SyncSchema.ReqRet as ReqRetModule
            import Wazuh.SyncSchema.Message as MessageModule
            import flatbuffers

            self.schema = {
                'Mode': ModeModule.Mode,
                'Operation': OperationModule.Operation,
                'Status': StatusModule.Status,
                'MessageType': MessageTypeModule.MessageType,
                'DataValue': DataModule.DataValue,
                'Start': StartModule.Start,
                'StartAck': StartAckModule.StartAck,
                'End': EndModule.End,
                'EndAck': EndAckModule.EndAck,
                'Pair': PairModule.Pair,
                'ReqRet': ReqRetModule.ReqRet,
                'Message': MessageModule.Message,
                'FlatBufferBuilder': flatbuffers.Builder
            }



        except ImportError as e:
            print(f"❌ Could not load generated classes: {e}")
            raise RuntimeError(f"Failed to load FlatBuffers classes: {e}")

    def get_schema(self):
        """Get the loaded schema."""
        return self.schema

    def create_message(self, message_type: str, data: dict) -> bytes:
        """Create a FlatBuffer message using real FlatBuffers classes."""
        if not self.schema:
            raise RuntimeError("No FlatBuffers schema loaded")

        try:
            import flatbuffers
            import time

            # Create FlatBuffer builder
            builder = self.schema['FlatBufferBuilder'](0)

            # Get the message type enum value
            if message_type == "start":
                msg_type = self.schema['MessageType'].Start

                # Import the functions from the Start module
                import Wazuh.SyncSchema.Start as StartModule

                # Create Start message
                module_str = builder.CreateString(data.get('module', 'syscollector'))
                agentid_str = builder.CreateString(data.get('agentid', '001'))
                agentname_str = builder.CreateString(data.get('agentname', 'test-agent'))
                agentversion_str = builder.CreateString(data.get('agentversion', '4.8.0'))

                StartModule.StartStart(builder)
                StartModule.StartAddModule(builder, module_str)
                StartModule.StartAddMode(builder, data.get('mode', 0))
                StartModule.StartAddSize(builder, data.get('size', 0))
                StartModule.StartAddAgentid(builder, agentid_str)
                StartModule.StartAddAgentname(builder, agentname_str)
                StartModule.StartAddAgentversion(builder, agentversion_str)
                start = StartModule.StartEnd(builder)
                content = start

            elif message_type == "data":
                msg_type = self.schema['MessageType'].DataValue

                # Import the functions from the DataValue module
                import Wazuh.SyncSchema.DataValue as DataModule

                # Handle data field properly
                data_field = data.get('data', '')
                if isinstance(data_field, str):
                    data_bytes = data_field.encode('utf-8')
                elif isinstance(data_field, bytes):
                    data_bytes = data_field
                else:
                    # Convert dict/object to valid JSON string
                    import json
                    data_bytes = json.dumps(data_field).encode('utf-8')

                # Create byte vector for data
                data_vector = builder.CreateByteVector(data_bytes)

                # Create ID and index strings
                id_str = builder.CreateString(data.get('id', ''))
                index_str = builder.CreateString(data.get('index', ''))

                # Create DataValue message
                DataModule.DataValueStart(builder)
                DataModule.DataValueAddSeq(builder, data.get('seq', 0))
                DataModule.DataValueAddSession(builder, data.get('session', 0))
                DataModule.DataValueAddOperation(builder, data.get('operation', 0))
                DataModule.DataValueAddId(builder, id_str)
                DataModule.DataValueAddIndex(builder, index_str)
                DataModule.DataValueAddData(builder, data_vector)
                data_msg = DataModule.DataValueEnd(builder)
                content = data_msg

            elif message_type == "end":
                msg_type = self.schema['MessageType'].End

                # Import the functions from the End module
                import Wazuh.SyncSchema.End as EndModule

                # Create End message
                EndModule.EndStart(builder)
                EndModule.EndAddSession(builder, data.get('session', 0))
                end = EndModule.EndEnd(builder)
                content = end

            else:
                raise ValueError(f"Unknown message type: {message_type}")

            # Create Message wrapper
            import Wazuh.SyncSchema.Message as MessageModule

            MessageModule.MessageStart(builder)
            MessageModule.MessageAddContentType(builder, msg_type)
            MessageModule.MessageAddContent(builder, content)
            message = MessageModule.MessageEnd(builder)

            # Finish the buffer
            builder.Finish(message)

            # Return the buffer
            return bytes(builder.Output())

        except Exception as e:
            raise RuntimeError(f"Error creating FlatBuffer message: {e}")

    def parse_message(self, buffer: bytes) -> dict:
        """Parse a FlatBuffer message."""
        if not self.schema:
            raise RuntimeError("No FlatBuffers schema loaded")

        try:
            # Use the real FlatBuffers API to parse the message
            import Wazuh.SyncSchema.Message as MessageModule

            # Get the root message from the buffer
            message = MessageModule.Message.GetRootAsMessage(buffer, 0)

            if not message:
                return {"error": "Could not parse message"}

            # Get the message type
            content_type = message.ContentType()

            # Parse based on content type
            if content_type == self.schema['MessageType'].StartAck:
                # Get the union table and cast it to StartAck
                content_table = message.Content()
                if content_table:
                    import Wazuh.SyncSchema.StartAck as StartAckModule
                    start_ack = StartAckModule.StartAck()
                    start_ack.Init(content_table.Bytes, content_table.Pos)

                    return {
                        'type': 'start_ack',
                        'status': start_ack.Status(),
                        'session': start_ack.Session()
                    }
            elif content_type == self.schema['MessageType'].EndAck:
                # Get the union table and cast it to EndAck
                content_table = message.Content()
                if content_table:
                    import Wazuh.SyncSchema.EndAck as EndAckModule
                    end_ack = EndAckModule.EndAck()
                    end_ack.Init(content_table.Bytes, content_table.Pos)

                    return {
                        'type': 'end_ack',
                        'status': end_ack.Status(),
                        'session': end_ack.Session()
                    }
            elif content_type == self.schema['MessageType'].DataValue:
                content = message.ContentAsData()
                if content:
                    return {
                        'type': 'data',
                        'seq': content.Seq(),
                        'session': content.Session(),
                        'operation': content.Operation(),
                        'id': content.Id().decode('utf-8') if content.Id() else '',
                        'index': content.Index().decode('utf-8') if content.Index() else '',
                        'data': content.DataAsNumpy().tobytes() if content.DataLength() > 0 else b''
                    }
            elif content_type == self.schema['MessageType'].Start:
                content = message.ContentAsStart()
                if content:
                    return {
                        'type': 'start',
                        'mode': content.Mode(),
                        'size': content.Size(),
                        'module': content.Module().decode('utf-8') if content.Module() else ''
                    }
            elif content_type == self.schema['MessageType'].End:
                content = message.ContentAsEnd()
                if content:
                    return {
                        'type': 'end',
                        'session': content.Session()
                    }
            elif content_type == self.schema['MessageType'].ReqRet:
                # Get the union table and cast it to ReqRet
                content_table = message.Content()
                if content_table:
                    import Wazuh.SyncSchema.ReqRet as ReqRetModule
                    req_ret = ReqRetModule.ReqRet()
                    req_ret.Init(content_table.Bytes, content_table.Pos)

                    # Parse the sequence ranges
                    ranges = []
                    for i in range(req_ret.SeqLength()):
                        pair = req_ret.Seq(i)
                        if pair:
                            ranges.append({
                                'start': pair.Begin(),
                                'end': pair.End()
                            })

                    return {
                        'type': 'reqret',
                        'session': req_ret.Session(),
                        'ranges': ranges
                    }
            else:
                return {
                    'type': 'unknown',
                    'content_type': content_type
                }

        except Exception as e:
            return {"error": f"Parse error: {e}"}

# Global instance
_flatbuffers_manager = None

def get_flatbuffers_manager():
    """Get the global FlatBuffers manager instance."""
    global _flatbuffers_manager
    if _flatbuffers_manager is None:
        _flatbuffers_manager = FlatBuffersManager()
    return _flatbuffers_manager

def get_schema():
    """Get the FlatBuffers schema."""
    return get_flatbuffers_manager().get_schema()

def create_message(message_type: str, data: dict) -> bytes:
    """Create a FlatBuffer message."""
    return get_flatbuffers_manager().create_message(message_type, data)

def parse_message(buffer: bytes) -> dict:
    """Parse a FlatBuffer message."""
    return get_flatbuffers_manager().parse_message(buffer)
