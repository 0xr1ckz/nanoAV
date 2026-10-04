# Byte ingestion and PE parsing

import pefile
import pathlib

class Scanner:
    def __init__(self, target: str | bytes):
        if isinstance(target, (str, pathlib.pathlib)):
            with open(target, "rb") as f:
                self.raw = f.read()
        else:
            self.raw = target # raw bytes from memory dump

        self.pe = None
        self._parse_pe()

    def _parse_pe(self):
        try:
            self.pe = pefile.PE(data=self.raw)
        except pefile.PEFormatError:
            self.pe = None # Not a PE - still scan raw bytes

    def get_selections(self) -> list[dict]:
        if not self.pe:
            return [{"name": "raw", "data": self.raw}]
        return [ 
            {
                "name": s.Name.decode(errors="replace").strip("\x00"),
                "data": s.get_data(),
                "virtual_address": s.VirtualAddress,
                "characteristics": s.Characteristics,
            }
            for s in self.pe.section
        ]
def get_raw(self) -> bytes:
    return self.raw