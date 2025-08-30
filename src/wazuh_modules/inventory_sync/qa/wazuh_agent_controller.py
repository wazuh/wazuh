#!/usr/bin/env python3
"""
Wazuh Agent Controller
Script to register agents and send arbitrary payloads using the Wazuh protocol.
"""

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import zlib
import base64
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from random import sample
from string import ascii_letters
from time import sleep


class Cipher:
    """Class to encrypt/decrypt messages using AES or Blowfish."""
    
    def __init__(self, data, key):
        self.block_size = 16
        self.data = data
        self.key_blowfish = key
        self.key_aes = key[:32]

    def encrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(self.data, self.block_size))

    def decrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.decrypt(pad(self.data, self.block_size))

    def encrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.encrypt(self.data)

    def decrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.decrypt(self.data)


class WazuhAgent:
    """Class to simulate a Wazuh agent."""
    
    def __init__(self, manager_address, registration_address=None, cypher="aes", 
                 os="debian8", version="v4.3.0", authd_password=None, enable_flatbuffer=False):
        self.manager_address = manager_address
        self.registration_address = registration_address or manager_address
        self.cypher = cypher
        self.os = os
        self.version = version
        self.authd_password = authd_password
        self.enable_flatbuffer = enable_flatbuffer
        
        # Agent values (set during registration)
        self.id = None
        self.name = None
        self.key = None
        self.encryption_key = None
        
        # Global counter for unique names
        self.agent_count = 0
        
        # Persistent connection
        self.persistent_socket = None
        self.persistent_ssl_socket = None
        
        # File to save credentials
        self.credentials_file = "wazuh_agents.json"
        
        # FlatBuffers serializer (simplified)
        # Initialize FlatBuffers manager
        try:
            from flatbuffers_manager import get_schema
            self.schema = get_schema()
            print("✅ FlatBuffers schema loaded")
        except ImportError:
            self.schema = None
            print("⚠️  FlatBuffers schema not available")

    def generate_agent_name(self):
        """Generates a unique name for the agent."""
        random_string = ''.join(sample(f"0123456789{ascii_letters}", 16))
        self.agent_count += 1
        return f"{self.agent_count}-{random_string}-{self.os}"

    def load_credentials(self):
        """Loads saved agent credentials."""
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Error loading credentials: {e}")
                return {}
        return {}

    def save_credentials(self, credentials):
        """Saves agent credentials."""
        try:
            with open(self.credentials_file, 'w') as f:
                json.dump(credentials, f, indent=2)
        except Exception as e:
                print(f"⚠️  Error saving credentials: {e}")

    def get_agent_credentials(self, agent_id):
        """Gets agent credentials by ID."""
        credentials = self.load_credentials()
        return credentials.get(agent_id)

    def list_registered_agents(self):
        """Lists all registered agents."""
        credentials = self.load_credentials()
        if not credentials:
            print("📋 No registered agents.")
            return []
        
        print("📋 Registered agents:")
        print("-" * 60)
        for agent_id, agent_data in credentials.items():
            print(f"ID: {agent_id}")
            print(f"  Name: {agent_data['name']}")
            print(f"  Key: {agent_data['key']}")
            print(f"  Manager: {agent_data['manager']}")
            print(f"  Cipher: {agent_data['cypher']}")
            print(f"  OS: {agent_data['os']}")
            print(f"  Version: {agent_data['version']}")
            print("-" * 60)
        
        return list(credentials.keys())

    def register_agent(self, agent_name=None):
        """Registers the agent with the manager."""
        if agent_name:
            self.name = agent_name
        else:
            self.name = self.generate_agent_name()
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            ssl_socket = context.wrap_socket(sock, server_hostname=self.registration_address)
            ssl_socket.connect((self.registration_address, 1515))

            if self.authd_password is None:
                event = f"OSSEC A:'{self.name}'\n".encode()
            else:
                event = f"OSSEC PASS: {self.authd_password} OSSEC A:'{self.name}'\n".encode()

            ssl_socket.send(event)
            recv = ssl_socket.recv(4096)
            registration_info = recv.decode().split("'")[1].split(" ")

            self.id = registration_info[0]
            self.key = registration_info[3]
            
            # Save credentials
            credentials = self.load_credentials()
            credentials[self.id] = {
                'name': self.name,
                'key': self.key,
                'manager': self.manager_address,
                'cypher': self.cypher,
                'os': self.os,
                'version': self.version
            }
            self.save_credentials(credentials)
            
            print(f"✅ Agent registered successfully:")
            print(f"   ID: {self.id}")
            print(f"   Name: {self.name}")
            print(f"   Key: {self.key}")
            print(f"   Credentials saved in: {self.credentials_file}")
            
            # Wait 10 seconds after registration to ensure manager processes it
            print("⏳ Waiting 10 seconds after agent registration...")
            import time
            time.sleep(10)
            print("✅ Registration wait completed")
            
            # Create encryption key for communication
            self.create_encryption_key()
            
            # Send control message (startup message)
            print("📤 Sending control message (startup)...")
            self.send_control_message()
            print("✅ Control message sent")
            
        except Exception as e:
            print(f"❌ Error during registration: {e}")
            raise
        finally:
            ssl_socket.close()
            sock.close()

    def send_control_message(self):
        """Send control message (startup message) to the manager."""
        try:
            # Create persistent connection first
            if not self.create_persistent_connection():
                raise RuntimeError("Failed to create persistent connection")
            
            # Create agent info JSON
            import json
            agent_info = {
                "version": "4.8.0",  # Wazuh version
                "name": self.name,
                "id": self.id
            }
            agent_info_string = json.dumps(agent_info)
            
            # Create control message
            control_msg = f"#!-agent startup {agent_info_string}"
            
            print(f"   Control message: {control_msg}")
            
            # Send the control message using persistent connection
            self.send_payload(control_msg, persistent=True, expect_response=True)
            
            # Wait 2 seconds after startup message
            print("⏳ Waiting 2 seconds after startup message...")
            import time
            time.sleep(2)
            print("✅ Startup wait completed")
            
        except Exception as e:
            print(f"❌ Error sending control message: {e}")
            import traceback
            traceback.print_exc()

    def create_encryption_key(self):
        """Generates the encryption key using agent metadata."""
        if not all([self.id, self.name, self.key]):
            raise ValueError("Agent must be registered before creating encryption key")
            
        agent_id = self.id.encode()
        name = self.name.encode()
        key = self.key.encode()
        
        sum1 = hashlib.md5(hashlib.md5(name).hexdigest().encode() + 
                          hashlib.md5(agent_id).hexdigest().encode()).hexdigest().encode()
        sum1 = sum1[:15]
        sum2 = hashlib.md5(key).hexdigest().encode()
        self.encryption_key = sum2 + sum1

    def wazuh_padding(self, compressed_event):
        """Adds Wazuh's custom padding to the event."""
        padding = 8
        extra = len(compressed_event) % padding
        if extra > 0:
            padded_event = (b'!' * (padding - extra)) + compressed_event
        else:
            padded_event = (b'!' * padding) + compressed_event
        return padded_event

    def compose_event(self, message):
        """Composes the event from the raw message."""
        message = message.encode()
        return self.compose_event_from_data(message)
    
    def compose_event_from_data(self, data):
        """Composes the event from binary data."""
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        msg = random_number + global_counter + split + local_counter + split + data
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        return event

    def encrypt(self, padded_event):
        """Encrypts the event using AES or Blowfish."""
        if self.cypher == "aes":
            return Cipher(padded_event, self.encryption_key).encrypt_aes()
        elif self.cypher == "blowfish":
            return Cipher(padded_event, self.encryption_key).encrypt_blowfish()
        else:
            raise ValueError(f"Unsupported cipher: {self.cypher}")

    def headers(self, agent_id, encrypted_event):
        """Adds event headers for AES or Blowfish."""
        if self.cypher == "aes":
            header = f"!{agent_id}!#AES:".encode()
        elif self.cypher == "blowfish":
            header = f"!{agent_id}!:".encode()
        else:
            raise ValueError(f"Unsupported cipher: {self.cypher}")
        return header + encrypted_event

    def create_event(self, message):
        """Builds a complete event from a raw message."""
        # Normal text message
        event_data = message.encode()
        
        # Compose event
        event = self.compose_event_from_data(event_data)
        # Compress
        compressed_event = zlib.compress(event)
        # Padding
        padded_event = self.wazuh_padding(compressed_event)
        # Encrypt
        encrypted_event = self.encrypt(padded_event)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)
        return headers_event
    
    def create_event_from_binary(self, identifier, binary_data):
        """Builds a complete event from binary data (FlatBuffers)."""
        # Create the event structure with identifier and binary data
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        
        # Combine identifier and binary data with s: prefix
        identifier_bytes = identifier.encode()
        s_prefix = b's:'
        msg = random_number + global_counter + split + local_counter + split + s_prefix + identifier_bytes + split + binary_data
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        

        
        # Compress
        compressed_event = zlib.compress(event)
        # Padding
        padded_event = self.wazuh_padding(compressed_event)
        # Encrypt
        encrypted_event = self.encrypt(padded_event)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)
        
        return headers_event

    def process_flatbuffer_payload(self, payload):
        """Processes payload with format 's:xxx:data' where data is JSON to be serialized as FlatBuffers."""
        if not self.enable_flatbuffer or not payload.startswith('s:'):
            return payload, None
        
        try:
            # Parse the format: s:xxx:data
            parts = payload.split(':', 2)
            if len(parts) != 3:
                print(f"⚠️  Invalid FlatBuffers payload format. Expected 's:xxx:data', got: {payload}")
                return payload, None
            
            prefix, identifier, json_data = parts
            
            # Parse JSON data
            try:
                json_obj = json.loads(json_data)
            except json.JSONDecodeError as e:
                print(f"⚠️  Invalid JSON in FlatBuffers payload: {e}")
                return payload, None
            
            # Use FlatBuffers manager to create message
            if self.schema:
                try:
                    from flatbuffers_manager import create_message
                    message_type = json_obj.get("type", "data")
                    message_data = {k: v for k, v in json_obj.items() if k != "type"}
                    
                    flatbuffer_data = create_message(message_type, message_data)
                    
                    print(f"✅ FlatBuffers payload processed:")
                    print(f"   Message type: {message_type}")
                    print(f"   Original JSON: {json_data}")
                    print(f"   Serialized size: {len(flatbuffer_data)} bytes")
                    
                    return identifier, flatbuffer_data
                    
                except Exception as e:
                    print(f"⚠️  Error creating FlatBuffer message: {e}")
                    # Fallback to JSON encoding
                    return identifier, json.dumps(json_obj).encode('utf-8')
            else:
                # No schema available, use JSON encoding
                return identifier, json.dumps(json_obj).encode('utf-8')
            
        except Exception as e:
            print(f"⚠️  Error processing FlatBuffers payload: {e}")
            return payload, None

    def send_payload(self, payload, protocol="TCP", port=1514, persistent=None, expect_response=False, timeout=10.0):
        """Sends an arbitrary payload to the manager and optionally waits for response."""
        import struct
        import socket
        
        if not all([self.id, self.name, self.key, self.encryption_key]):
            raise ValueError("Agent must be registered and have encryption key")
        
        # Process FlatBuffers payload if needed
        processed_result = self.process_flatbuffer_payload(payload)
        
        if isinstance(processed_result, tuple) and len(processed_result) == 2:
            # FlatBuffers processing returned (identifier, binary_data)
            identifier, flatbuffer_data = processed_result
            if flatbuffer_data is not None:
                # Create event directly from binary data
                encrypted_event = self.create_event_from_binary(identifier, flatbuffer_data)
            else:
                # Fallback to normal processing
                encrypted_event = self.create_event(payload)
        else:
            # Normal processing
            encrypted_event = self.create_event(payload)
        
        response = None
        
        # Determine if we should use persistent connection
        use_persistent = persistent
        if persistent is None:
            # If persistent is None, use persistent connection if available
            use_persistent = self.persistent_socket is not None
        
        # Send using persistent connection or new connection
        if use_persistent and self.persistent_socket:
            try:
                length = struct.pack('<I', len(encrypted_event))
                self.persistent_socket.send(length + encrypted_event)
                print(f"✅ Payload sent (persistent connection):")
                print(f"   Agent: {self.name} (ID: {self.id})")
                print(f"   Original payload: {payload}")
                if isinstance(processed_result, tuple) and processed_result[1] is not None:
                    print(f"   Processed as FlatBuffers binary: {len(processed_result[1])} bytes")
                print(f"   Protocol: {protocol}")
                print(f"   Destination: {self.manager_address}:{port}")
                
                if expect_response:
                    response = self._receive_response(self.persistent_socket, timeout)
                return response
            except Exception as e:
                print(f"⚠️  Error in persistent connection, creating new one: {e}")
                self.close_persistent_connection()
        
        # Connect and send (if not using persistent or persistent failed)
        if protocol.upper() == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((self.manager_address, port))
                length = struct.pack('<I', len(encrypted_event))
                sock.send(length + encrypted_event)
                
                if expect_response:
                    response = self._receive_response(sock, timeout)
                    
            finally:
                sock.close()
        elif protocol.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(encrypted_event, (self.manager_address, port))
            sock.close()
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
        print(f"✅ Payload sent successfully:")
        print(f"   Agent: {self.name} (ID: {self.id})")
        print(f"   Original payload: {payload}")
        if isinstance(processed_result, tuple) and processed_result[1] is not None:
            print(f"   Processed as FlatBuffers binary: {len(processed_result[1])} bytes")
        print(f"   Protocol: {protocol}")
        print(f"   Destination: {self.manager_address}:{port}")
        
        return response

    def _receive_response(self, sock, timeout=10.0):
        """Receive and decode response from the manager."""
        import struct
        import zlib
        
        try:
            # Set socket timeout for response
            sock.settimeout(timeout)
            
            # Receive response length (first 4 bytes)
            length_data = sock.recv(4)
            if not length_data:
                return None
                
            response_length = struct.unpack('<I', length_data)[0]
            print(f"📥 Expecting response of {response_length} bytes")
            
            # Receive the actual response
            response_data = b''
            while len(response_data) < response_length:
                chunk = sock.recv(response_length - len(response_data))
                if not chunk:
                    break
                response_data += chunk
            
            if len(response_data) != response_length:
                print(f"⚠️  Incomplete response: got {len(response_data)}, expected {response_length}")
                return None
            
            print(f"📥 Received response: {len(response_data)} bytes")
            
            # Check if it's an AES encrypted response
            if response_data.startswith(b"#AES:"):
                # Remove the #AES: prefix and decrypt
                encrypted_data = response_data[5:]  # Remove '#AES:' prefix
                
                # Decrypt using the same process as agent communication
                cipher = Cipher(encrypted_data, self.encryption_key)
                decrypted_padded = cipher.decrypt_aes()
                
                # Remove Wazuh padding (leading !)
                i = 0
                while i < len(decrypted_padded) and decrypted_padded[i] == ord('!'):
                    i += 1
                decrypted_data = decrypted_padded[i:]
                
                # Decompress
                decompressed_data = zlib.decompress(decrypted_data)
                
                # Extract the message (skip MD5 hash + random + counters)
                # Format: MD5(32) + random(5) + global_counter(10) + : + local_counter(4) + : + message
                md5_end = 32
                random_end = md5_end + 5
                global_counter_end = random_end + 10
                colon1 = global_counter_end
                local_counter_end = colon1 + 1 + 4
                colon2 = local_counter_end
                
                if colon2 + 1 < len(decompressed_data):
                    message = decompressed_data[colon2 + 1:]
                    
                    # Try to parse as FlatBuffer or JSON
                    if message.startswith(b's:'):
                        # s:identifier:data format
                        parts = message.decode('utf-8', errors='replace').split(':', 2)
                        if len(parts) >= 3:
                            identifier = parts[1]
                            data_part = parts[2]
                            
                            # Try to parse the data part as FlatBuffer
                            if self.schema:
                                try:
                                    from flatbuffers_manager import parse_message
                                    # The data_part might be binary FlatBuffer data
                                    fb_bytes = data_part.encode('latin-1')
                                    
                                    flatbuffer_response = parse_message(fb_bytes)
                                    print(f"📥 FlatBuffer Response: {flatbuffer_response}")
                                    
                                    return {
                                        'type': 'flatbuffer',
                                        'identifier': identifier,
                                        'data': flatbuffer_response
                                    }
                                except Exception as e:
                                    print(f"❌ Error parsing FlatBuffer: {e}")
                                    # Fall back to returning the raw data
                                    return {
                                        'type': 'unknown',
                                        'identifier': identifier,
                                        'raw_data': data_part,
                                        'error': str(e)
                                    }
                            else:
                                return {
                                    'type': 'unknown',
                                    'identifier': identifier,
                                    'raw_data': data_part
                                }
                    elif message.startswith(b'#!-'):
                        # This could be a control message or FlatBuffer message with module prefix
                        
                        # Find the space after the prefix
                        space_pos = message.find(b' ')
                        if space_pos != -1:
                            prefix = message[:space_pos].decode('utf-8')
                            data_after_space = message[space_pos + 1:]
                            
                            # Check if this is a control message (like #!-agent)
                            if prefix.startswith('#!-agent'):
                                # This is a control message, data after space is plain text
                                text_data = data_after_space.decode('utf-8', errors='replace')
                                print(f"📥 Control Response: {prefix} {text_data.strip()}")
                                
                                return {
                                    'type': 'control_ack',
                                    'command': prefix,
                                    'message': text_data.strip(),
                                    'raw': message.decode('utf-8', errors='replace')
                                }
                            
                            # Check if this is a module message with FlatBuffer data
                            elif prefix.startswith('#!-') and ('sync' in prefix or 'inventory' in prefix):
                                # This is likely a FlatBuffer message with module prefix
                                
                                # Try to parse the FlatBuffer data
                                if self.schema:
                                    try:
                                        from flatbuffers_manager import parse_message
                                        flatbuffer_response = parse_message(data_after_space)
                                        print(f"📥 FlatBuffer Response: {flatbuffer_response}")
                                        
                                        return {
                                            'type': 'flatbuffer',
                                            'identifier': prefix,
                                            'data': flatbuffer_response
                                        }
                                    except Exception as e:
                                        print(f"❌ Error parsing FlatBuffer: {e}")
                                        return {
                                            'type': 'flatbuffer_with_prefix',
                                            'module_prefix': prefix,
                                            'raw_data': data_after_space.hex(),
                                            'error': str(e)
                                        }
                                else:
                                    return {
                                        'type': 'flatbuffer_with_prefix',
                                        'module_prefix': prefix,
                                        'raw_data': data_after_space.hex()
                                    }
                            else:
                                # Unknown type of #!- message
                                return {
                                    'type': 'unknown_control',
                                    'prefix': prefix,
                                    'data': data_after_space.decode('utf-8', errors='replace'),
                                    'raw': message.decode('utf-8', errors='replace')
                                }
                    else:
                        # Try to decode as text
                        try:
                            text_response = message.decode('utf-8')
                            return {
                                'type': 'text',
                                'data': text_response
                            }
                        except:
                            return {
                                'type': 'binary',
                                'raw_data': message.hex(),
                                'size': len(message)
                            }
                else:
                    return {
                        'type': 'raw_binary',
                        'raw_data': decompressed_data.hex(),
                        'size': len(decompressed_data)
                    }
            
            # Check if it's a control message
            try:
                response_str = response_data.decode('utf-8')
                if response_str.startswith('#!-'):
                    return self._parse_control_response(response_str)
            except UnicodeDecodeError:
                pass
            
            # Fallback to raw response
            return self._parse_raw_response(response_data)
        
        except Exception as e:
            print(f"⚠️  Error receiving response: {e}")
            return None
    
    def _decrypt_response(self, encrypted_data):
        """Decrypt response data using the agent's encryption key."""
        if self.cypher == "aes":
            return Cipher(encrypted_data, self.encryption_key).decrypt_aes()
        elif self.cypher == "blowfish":
            return Cipher(encrypted_data, self.encryption_key).decrypt_blowfish()
        else:
            raise ValueError(f"Unsupported cipher: {self.cypher}")
    
    def _parse_control_response(self, response_str):
        """Parse control message response."""
        try:
            # Handle binary data that can't be decoded as UTF-8
            if isinstance(response_str, bytes):
                return {
                    'type': 'raw_binary',
                    'raw_hex': response_str.hex(),
                    'session': None
                }
            
            if response_str.startswith('#!-agent ack'):
                return {
                    'type': 'control_ack',
                    'message': 'agent ack',
                    'session': None
                }
            elif response_str.startswith('#!-agent startup'):
                # Extract session from startup response
                import re
                session_match = re.search(r'"session":\s*(\d+)', response_str)
                session = session_match.group(1) if session_match else None
                return {
                    'type': 'startup_response',
                    'message': 'startup',
                    'session': session
                }
            else:
                return {
                    'type': 'control_response',
                    'message': response_str.strip(),
                    'session': None
                }
        except Exception as e:
            return {
                'type': 'control_response',
                'message': str(response_str)[:100] if response_str else 'None',
                'session': None,
                'error': str(e)
            }

    def _parse_raw_response(self, response_data):
        """Parse raw response data."""
        try:
            # Try to decode as string
            response_str = response_data.decode('utf-8', errors='ignore')
            return {
                'type': 'raw_text',
                'data': response_str,
                'raw_hex': response_data.hex()
            }
        except:
            return {
                'type': 'raw_binary',
                'raw_hex': response_data.hex()
            }

    def _parse_response(self, response_data):
        """Parse the decompressed response data - this should be used with properly processed data."""
        try:
            # This method expects already processed data (after decryption, decompression, padding removal)
            # Try to decode as UTF-8 first
            try:
                response_str = response_data.decode('utf-8')
                
                # Check if it's in s:identifier:data format
                if response_str.startswith('s:'):
                    parts = response_str.split(':', 2)
                    if len(parts) >= 3:
                        identifier = parts[1]
                        data_part = parts[2]
                        
                        # Try to parse as JSON first
                        try:
                            import json
                            json_data = json.loads(data_part)
                            return {
                                'type': 'json',
                                'identifier': identifier,
                                'data': json_data
                            }
                        except:
                            # It might be binary FlatBuffer data
                            if self.schema:
                                try:
                                    from flatbuffers_manager import parse_message
                                    # Convert string back to bytes for FlatBuffer parsing
                                    flatbuffer_response = parse_message(data_part.encode('latin-1'))
                                    return {
                                        'type': 'flatbuffer',
                                        'identifier': identifier,
                                        'data': flatbuffer_response
                                    }
                                except Exception as e:
                                    return {
                                        'type': 'unknown',
                                        'identifier': identifier,
                                        'raw_data': data_part.encode('latin-1').hex(),
                                        'error': str(e)
                                    }
                            else:
                                return {
                                    'type': 'unknown',
                                    'identifier': identifier,
                                    'raw_data': data_part.encode('latin-1').hex(),
                                    'error': 'No FlatBuffers schema available'
                                }
                
                # Try to parse as JSON directly
                try:
                    import json
                    json_data = json.loads(response_str)
                    return {
                        'type': 'json',
                        'data': json_data
                    }
                except:
                    pass
                    
            except UnicodeDecodeError:
                # Data is binary, handle directly as FlatBuffer
                pass
            
            # Try to parse as direct FlatBuffer binary data
            if self.schema:
                try:
                    from flatbuffers_manager import parse_message
                    flatbuffer_response = parse_message(response_data)
                    return {
                        'type': 'flatbuffer',
                        'data': flatbuffer_response
                    }
                except Exception as e:
                    # Return raw data for debugging
                    return {
                        'type': 'raw_binary',
                        'raw_data': response_data.hex(),
                        'size': len(response_data),
                        'error': str(e)
                    }
            else:
                # No schema available, return raw data
                return {
                    'type': 'raw_binary',
                    'raw_data': response_data.hex(),
                    'size': len(response_data)
                }
            
        except Exception as e:
            # Handle any other errors
            return {
                'type': 'error',
                'raw_data': response_data.hex() if response_data else 'None',
                'size': len(response_data) if response_data else 0,
                'error': str(e)
            }

    def load_existing_agent(self, agent_id, agent_name=None, agent_key=None):
        """Loads an existing agent with its credentials."""
        # Try to load from credentials file
        if agent_name is None and agent_key is None:
            agent_data = self.get_agent_credentials(agent_id)
            if agent_data:
                self.id = agent_id
                self.name = agent_data['name']
                self.key = agent_data['key']
                self.cypher = agent_data.get('cypher', 'aes')
                self.os = agent_data.get('os', 'debian8')
                self.version = agent_data.get('version', 'v4.3.0')
                self.manager_address = agent_data.get('manager', self.manager_address)
                print(f"✅ Agent loaded from saved credentials:")
                print(f"   ID: {self.id}")
                print(f"   Name: {self.name}")
                print(f"   Key: {self.key}")
            else:
                raise ValueError(f"No credentials found for agent ID: {agent_id}")
        else:
            # Use provided credentials
            self.id = agent_id
            self.name = agent_name
            self.key = agent_key
        
        self.create_encryption_key()

    def create_persistent_connection(self):
        """Creates a persistent connection to the manager."""
        import socket
        
        if self.persistent_socket:
            print("🔌 Closing existing persistent connection")
            self.close_persistent_connection()
        
        try:
            self.persistent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.persistent_socket.connect((self.manager_address, 1514))
            print("🔌 Persistent connection established")
            return True
        except Exception as e:
            print(f"❌ Error creating persistent connection: {e}")
            self.persistent_socket = None
            return False

    def close_persistent_connection(self):
        """Closes the persistent connection."""
        if self.persistent_socket:
            self.persistent_socket.close()
            self.persistent_socket = None
            print("🔌 Persistent connection closed")


def main():
    parser = argparse.ArgumentParser(description="Wazuh Agent Controller")
    parser.add_argument('-m', '--manager', required=True, help='Manager IP address')
    parser.add_argument('-r', '--registration-address', help='Registration IP address (defaults to manager)')
    parser.add_argument('-p', '--protocol', default='TCP', choices=['TCP', 'UDP'], help='Communication protocol')
    parser.add_argument('-c', '--cypher', default='aes', choices=['aes', 'blowfish'], help='Encryption method')
    parser.add_argument('-o', '--os', default='debian8', help='Agent operating system')
    parser.add_argument('-v', '--version', default='v4.3.0', help='Agent version')
    parser.add_argument('--authd-password', help='Registration password')
    parser.add_argument('--port', type=int, default=1514, help='Manager port (default 1514)')
    parser.add_argument('--persistent', action='store_true', help='Use persistent connection')
    parser.add_argument('--flatbuffer', action='store_true', help='Enable FlatBuffers processing for s:xxx:data format')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register a new agent')
    register_parser.add_argument('-n', '--name', help='Agent name (optional, auto-generated)')
    
    # Send payload command
    send_parser = subparsers.add_parser('send', help='Send an arbitrary payload')
    send_parser.add_argument('--agent-id', required=True, help='Agent ID')
    send_parser.add_argument('--agent-name', help='Agent name (optional if saved)')
    send_parser.add_argument('--agent-key', help='Agent key (optional if saved)')
    send_parser.add_argument('--payload', required=True, help='Payload to send')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create agent instance
    agent = WazuhAgent(
        manager_address=args.manager,
        registration_address=args.registration_address,
        cypher=args.cypher,
        os=args.os,
        version=args.version,
        authd_password=args.authd_password,
        enable_flatbuffer=args.flatbuffer
    )
    
    try:
        if args.command == 'register':
            # Only register
            agent.register_agent(args.name)
            print("\n📋 Agent information for future use:")
            print(f"   --agent-id {agent.id}")
            print(f"   --agent-name {agent.name}")
            print(f"   --agent-key {agent.key}")
            
        elif args.command == 'send':
            # Load existing agent and send payload
            agent.load_existing_agent(args.agent_id, args.agent_name, args.agent_key)
            agent.send_payload(args.payload, args.protocol, args.port, args.persistent)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
