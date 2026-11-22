"""Example: build a P16-A capability delta from a P12 update."""
from pathlib import Path
from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.capability import CapabilityAnalyzer

def main():
    old_root=Path("data/examples/old_skill")
    new_root=Path("data/examples/new_skill")
    graph_delta=IncrementalBehaviorGraphAnalyzer().compare(old_root,new_root)
    analyzer=CapabilityAnalyzer()
    old_caps=analyzer.analyze(graph_delta.old_graph)
    new_caps=analyzer.analyze(graph_delta.new_graph)
    print(analyzer.compare(old_caps,new_caps).model_dump_json(indent=2))

if __name__=="__main__":
    main()
