# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tester.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import api_communication.proto.engine_pb2 as _engine_pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0ctester.proto\x12\x1b\x63om.wazuh.api.engine.tester\x1a\x0c\x65ngine.proto\"g\n\x0bSessionPost\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0e\n\x06policy\x18\x02 \x01(\t\x12\x10\n\x08lifetime\x18\x03 \x01(\r\x12\x18\n\x0b\x64\x65scription\x18\x04 \x01(\tH\x00\x88\x01\x01\x42\x0e\n\x0c_description\"\xe7\x01\n\x07Session\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0e\n\x06policy\x18\x02 \x01(\t\x12\x10\n\x08lifetime\x18\x03 \x01(\r\x12\x18\n\x0b\x64\x65scription\x18\x04 \x01(\tH\x00\x88\x01\x01\x12\x36\n\x0bpolicy_sync\x18\x06 \x01(\x0e\x32!.com.wazuh.api.engine.tester.Sync\x12\x38\n\x0c\x65ntry_status\x18\x07 \x01(\x0e\x32\".com.wazuh.api.engine.tester.State\x12\x10\n\x08last_use\x18\x08 \x01(\rB\x0e\n\x0c_description\"\x9c\x01\n\x06Result\x12\x0e\n\x06output\x18\x01 \x01(\t\x12\x44\n\x0c\x61sset_traces\x18\x02 \x03(\x0b\x32..com.wazuh.api.engine.tester.Result.AssetTrace\x1a<\n\nAssetTrace\x12\r\n\x05\x61sset\x18\x01 \x01(\t\x12\x0f\n\x07success\x18\x02 \x01(\x08\x12\x0e\n\x06traces\x18\x03 \x03(\t\"a\n\x13SessionPost_Request\x12>\n\x07session\x18\x01 \x01(\x0b\x32(.com.wazuh.api.engine.tester.SessionPostH\x00\x88\x01\x01\x42\n\n\x08_session\"%\n\x15SessionDelete_Request\x12\x0c\n\x04name\x18\x01 \x01(\t\"\"\n\x12SessionGet_Request\x12\x0c\n\x04name\x18\x01 \x01(\t\"\xaf\x01\n\x13SessionGet_Response\x12\x32\n\x06status\x18\x01 \x01(\x0e\x32\".com.wazuh.api.engine.ReturnStatus\x12\x12\n\x05\x65rror\x18\x02 \x01(\tH\x00\x88\x01\x01\x12:\n\x07session\x18\x03 \x01(\x0b\x32$.com.wazuh.api.engine.tester.SessionH\x01\x88\x01\x01\x42\x08\n\x06_errorB\n\n\x08_session\"%\n\x15SessionReload_Request\x12\x0c\n\x04name\x18\x01 \x01(\t\"\x12\n\x10TableGet_Request\"\x9d\x01\n\x11TableGet_Response\x12\x32\n\x06status\x18\x01 \x01(\x0e\x32\".com.wazuh.api.engine.ReturnStatus\x12\x12\n\x05\x65rror\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x36\n\x08sessions\x18\x03 \x03(\x0b\x32$.com.wazuh.api.engine.tester.SessionB\x08\n\x06_error\"\x95\x01\n\x0fRunPost_Request\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\r\n\x05\x65vent\x18\x02 \x01(\t\x12<\n\x0btrace_level\x18\x05 \x01(\x0e\x32\'.com.wazuh.api.engine.tester.TraceLevel\x12\x13\n\x0b\x61sset_trace\x18\x06 \x03(\t\x12\x12\n\nnamespaces\x18\x07 \x03(\t\"\xa9\x01\n\x10RunPost_Response\x12\x32\n\x06status\x18\x01 \x01(\x0e\x32\".com.wazuh.api.engine.ReturnStatus\x12\x12\n\x05\x65rror\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x38\n\x06result\x18\x03 \x01(\x0b\x32#.com.wazuh.api.engine.tester.ResultH\x01\x88\x01\x01\x42\x08\n\x06_errorB\t\n\x07_result*5\n\x05State\x12\x11\n\rSTATE_UNKNOWN\x10\x00\x12\x0c\n\x08\x44ISABLED\x10\x01\x12\x0b\n\x07\x45NABLED\x10\x02*>\n\x04Sync\x12\x10\n\x0cSYNC_UNKNOWN\x10\x00\x12\x0b\n\x07UPDATED\x10\x01\x12\x0c\n\x08OUTDATED\x10\x02\x12\t\n\x05\x45RROR\x10\x03*/\n\nTraceLevel\x12\x08\n\x04NONE\x10\x00\x12\x0e\n\nASSET_ONLY\x10\x01\x12\x07\n\x03\x41LL\x10\x02\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'tester_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _STATE._serialized_start=1452
  _STATE._serialized_end=1505
  _SYNC._serialized_start=1507
  _SYNC._serialized_end=1569
  _TRACELEVEL._serialized_start=1571
  _TRACELEVEL._serialized_end=1618
  _SESSIONPOST._serialized_start=59
  _SESSIONPOST._serialized_end=162
  _SESSION._serialized_start=165
  _SESSION._serialized_end=396
  _RESULT._serialized_start=399
  _RESULT._serialized_end=555
  _RESULT_ASSETTRACE._serialized_start=495
  _RESULT_ASSETTRACE._serialized_end=555
  _SESSIONPOST_REQUEST._serialized_start=557
  _SESSIONPOST_REQUEST._serialized_end=654
  _SESSIONDELETE_REQUEST._serialized_start=656
  _SESSIONDELETE_REQUEST._serialized_end=693
  _SESSIONGET_REQUEST._serialized_start=695
  _SESSIONGET_REQUEST._serialized_end=729
  _SESSIONGET_RESPONSE._serialized_start=732
  _SESSIONGET_RESPONSE._serialized_end=907
  _SESSIONRELOAD_REQUEST._serialized_start=909
  _SESSIONRELOAD_REQUEST._serialized_end=946
  _TABLEGET_REQUEST._serialized_start=948
  _TABLEGET_REQUEST._serialized_end=966
  _TABLEGET_RESPONSE._serialized_start=969
  _TABLEGET_RESPONSE._serialized_end=1126
  _RUNPOST_REQUEST._serialized_start=1129
  _RUNPOST_REQUEST._serialized_end=1278
  _RUNPOST_RESPONSE._serialized_start=1281
  _RUNPOST_RESPONSE._serialized_end=1450
# @@protoc_insertion_point(module_scope)
