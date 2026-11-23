"""Run the static-first end-to-end Skill update security pipeline."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skillupdate.pipeline import SkillUpdatePipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True, help="OLD Skill snapshot directory")
    parser.add_argument("--new", type=Path, required=True, help="NEW Skill snapshot directory")
    parser.add_argument("--update-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", default="")
    parser.add_argument("--version-old", default="")
    parser.add_argument("--version-new", default="")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output already exists; refusing to overwrite: {args.output}")
    result = SkillUpdatePipeline().run(
        args.old, args.new, update_id=args.update_id,
        skill_metadata={
            "name": args.name,
            "old_version": args.version_old,
            "new_version": args.version_new,
        },
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(args.output)
    print(json.dumps({
        "update_id": result.update_id,
        "snapshot_status": result.decision.snapshot_status,
        "update_impact": result.decision.update_impact,
        "new_scfg_paths": len(result.scfg_paths.added_paths),
        "scfg_coverage": result.scfg_paths.coverage,
        "output": str(args.output),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
