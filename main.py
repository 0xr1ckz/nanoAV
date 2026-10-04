import argparse
import json
from scanner import Scanner
from yara_engine import YARAEngine
from heuristics import HeuristicEngine
from verdict import VerdictEngine

def analyse(target: str, rules_dir: str = "rules/") -> dict:
    scanner = Scanner(target)
    yara_hits = YARAEngine(rules_dir).scan(scanner.get_raw())
    heur_hits = HeuristicEngine(scanner).run()
    verdict = VerdictEngine(yara_hits, heur_hits).compute()

    return {
        "target": target,
        "score": verdict.score,
        "level": verdict.level,
        "yara_matches": verdict.yara_matches,
        "heuristics": verdict.heuristics_findings,
        "timestamp": verdict.timestamp,
    }

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="AV Engine — memory forensics")
    parser.add_argument("target", help="Path to memory dump or PE file")
    parser.add_argument("--rules", default="rules/", help="YARA rules directory")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    rules = anaylse(args.target, args.rules)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n[*] Target : {result['target']}")
        print(f"[*] Score  : {result['score']}/100")
        print(f"[*] Level  : {result['level'].upper()}")
        print(f"[*] YARA   : {len(result['yara_matches'])} match(es)")
        print(f"[*] Heur   : {sum(len(v) for v in result['heuristics'].values() if isinstance(v, list))} finding(s)")
