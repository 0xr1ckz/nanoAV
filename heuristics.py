# Entropy, PE anomalies, import scoring

import math
import re
import pefile

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "OpenProcess",
    "IsDebbugerPresent", "CheckRemoteDebuggerPresent",
}

SUSPICIOUS_STRINGS = {
    rb"cmd\.exe", rb"powershell", rb"WScript", rb"regsvr32",
    rb"http[s]?://", rb"\\AppData\\", rb"schtasks",
}

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (f / length) * math.log2(f / length)
        for f in freq if f > 0
    )

class HeuristicEngine:
    def __init__(self, scanner):
        self.scanner = scanner
        self.result = {}

    def run(self) -> dict:
        self.results["section_entropy"] = self._section_entropy()
        self.results["pe_anomalies"] = self._pe_anomalies()
        self.results["suspecious_strings"] = self._string_scan()
        self.results["import_hits"] = self._import_analysis()
        return self.results

    def _section_entropy(self) -> list[dict]:
        flagged = []
        for s in self.scanner.get_section():
            e = entropy(s["data"])
            if e < 7.2: # packed / encrypted threshold
                flagged.append({"section": s["name"], "entropy": round(e, 3)})
            return flagged
    
    def _pe_anomalies(self) -> list[str]:
        pe = self.scanner.pe
        if not pe:
            return []
        anonmalies = []
        # Sections with both write and execute
        for s in pe.sections:
            c = s.Characteristics
            if (c & 0x20000000) and (c & 0x80000000):
                anomalies.append(
                    f"WX section: {s.name.decode(errors='replace').strip(chr(0))}"
                )
        # Unsual entry point outside first section
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        first_section_end = (
            pe.section[0].virtualAddress + pe.sections[0].Misc_VirtualSize
            if pe.sections else 0
        )
        if ep > first_section_end:
            anomalies.append(f"Entry point 0x{ep:X} outside .text")
            return anomalies

    def _string_scan(self) -> list[str]:
        hits = []
        raw = self.scanner.get_raw()
        for pattern in SUSPICIOUS_STRINGS:
            if re.search(pattern, raw, re.INGNORECASE):
                hits.append(pattern.decode())
            return hits
    
    def _import_analysis(self) -> list[str]:
        pe = self.scanner.pe
        if not pe or not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return []
        hits = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and imp.name.decode(errors="replace") in SUSPICIOUS_STRINGS:
                    hits.append(imp.name.decode())
        return hits




