"""Old/new graph construction, true fragment reuse, alignment, delta, and paths."""

from __future__ import annotations

import time
from pathlib import Path

from .alignment import align_edges, align_nodes
from .builder import BehavioralGraphBuilder
from .models import BehavioralGraphDelta, IncrementalStats
from .paths import find_new_risk_paths


class IncrementalBehaviorGraphAnalyzer:
    def __init__(self, builder: BehavioralGraphBuilder | None = None) -> None:
        self.builder = builder or BehavioralGraphBuilder()

    def compare(
        self, old_skill_directory: str | Path, new_skill_directory: str | Path
    ) -> BehavioralGraphDelta:
        started = time.perf_counter()
        old_snapshot = self.builder.snapshot(old_skill_directory)
        new_snapshot = self.builder.snapshot(new_skill_directory)
        old_fragments = self.builder.build_fragments(old_snapshot, "OLD")
        old_graph = self.builder.assemble(old_snapshot, old_fragments, "OLD")
        changed_files = sorted(
            file
            for file in set(old_snapshot.files) | set(new_snapshot.files)
            if old_snapshot.hashes.get(file) != new_snapshot.hashes.get(file)
        )
        reused_files = sorted(
            file
            for file in set(old_snapshot.files) & set(new_snapshot.files)
            if old_snapshot.hashes[file] == new_snapshot.hashes[file]
        )
        new_fragments = {
            file: self.builder.reuse_fragment(old_fragments[file])
            for file in reused_files
        }
        recomputed_files = sorted(
            file for file in new_snapshot.files if file not in reused_files
        )
        for file in recomputed_files:
            new_fragments[file] = self.builder.build_fragment(
                file, new_snapshot.files[file], new_snapshot.hashes[file], "NEW"
            )
        new_graph = self.builder.assemble(new_snapshot, new_fragments, "NEW")
        node_alignments = align_nodes(old_graph, new_graph)
        edge_alignments = align_edges(old_graph, new_graph, node_alignments)
        aligned_old_nodes = {item.old_node_id for item in node_alignments}
        aligned_new_nodes = {item.new_node_id for item in node_alignments}
        aligned_old_edges = {item.old_edge_id for item in edge_alignments}
        aligned_new_edges = {item.new_edge_id for item in edge_alignments}
        added_nodes = [
            node for node in new_graph.nodes if node.node_id not in aligned_new_nodes
        ]
        removed_nodes = [
            node for node in old_graph.nodes if node.node_id not in aligned_old_nodes
        ]
        added_edges = [
            edge for edge in new_graph.edges if edge.edge_id not in aligned_new_edges
        ]
        removed_edges = [
            edge for edge in old_graph.edges if edge.edge_id not in aligned_old_edges
        ]
        new_risk_paths = find_new_risk_paths(
            new_graph,
            {node.node_id for node in added_nodes},
            {edge.edge_id for edge in added_edges},
        )
        return BehavioralGraphDelta(
            old_graph=old_graph,
            new_graph=new_graph,
            node_alignments=node_alignments,
            edge_alignments=edge_alignments,
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            added_edges=added_edges,
            removed_edges=removed_edges,
            new_risk_paths=new_risk_paths,
            incremental_stats=IncrementalStats(
                changed_files=changed_files,
                reused_files=reused_files,
                recomputed_files=recomputed_files,
                globally_rebuilt_relations=["REFERENCES", "CALLS", "CONNECTS_TO"],
            ),
            processing_time_ms=(time.perf_counter() - started) * 1000,
        )

    def build_full(self, skill_directory: str | Path, side: str = "NEW"):
        snapshot = self.builder.snapshot(skill_directory)
        fragments = self.builder.build_fragments(snapshot, side)
        return self.builder.assemble(snapshot, fragments, side)
