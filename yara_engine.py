# Yara scanning layer
import yara
import pathlib

class YARAEngine:
    def __init__(self, rules_dir: str = "rules/"):
        rules_files = {
            p.stem: str(p)
            for p in pathlib.Path(rules_dir).glob("*.yar")
        }
        self.rules = yara.compile(filepath=rules_files) if rules_files else None

    def scan(self, data: bytes) -> list[dict]:
        if not self.rules:
            return []
        matches = self.rules.match(data=data)
        return [
            {
                "rule": m.rule,
                "tags": m.tags,
                "strings": [ 
                    {
                    "offset": s.instances[0].offset,
                    "identifier": s.identifier,
                    "data": s.instance[0].matched_data[:64].hex(),
                    }
                    for s in m.strings
                ],
            }
            for m in matches
        ]

