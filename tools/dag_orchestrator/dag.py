"""
DAG-based Agent Orchestrator core.
Supports parallel execution of independent nodes and feedback edges.
"""
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import networkx as nx


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentNode:
    """Represents a single agent node in the DAG."""
    name: str
    role: str                         # scout, analyst, reporter, etc.
    model: str = "sonnet"             # claude model alias
    description: str = ""
    handler: Optional[Callable] = None  # actual execution function
    timeout: int = 300                # seconds
    retry_limit: int = 2
    # Performance tuning (Wave 3 upgrade)
    effort: str = "default"
    max_turns: Optional[int] = None
    allowed_tools: list = field(default_factory=list)
    disallowed_tools: list = field(default_factory=list)
    # Runtime state
    status: NodeStatus = NodeStatus.PENDING
    output: Any = None
    error: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    retries: int = 0

    def duration(self) -> float:
        if self.started_at and self.finished_at:
            return self.finished_at - self.started_at
        return 0.0


class AgentDAG:
    """
    networkx-based DAG for agent pipeline orchestration.
    Supports:
    - Parallel execution of independent nodes
    - Sequential dependencies
    - Feedback edges (retry loops)
    - Pipeline state persistence
    """

    def __init__(self, name: str, max_workers: int = 4):
        self.name = name
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, AgentNode] = {}
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._context: Dict[str, Any] = {}  # shared context across nodes

    def add_node(self, node: AgentNode) -> "AgentDAG":
        """Add an agent node to the DAG."""
        self.nodes[node.name] = node
        self.graph.add_node(node.name, role=node.role, model=node.model)
        return self

    def add_edge(self, from_node: str, to_node: str, feedback: bool = False) -> "AgentDAG":
        """
        Add dependency edge. If feedback=True, marks as a retry/feedback loop.
        Feedback edges do NOT enforce topological ordering.
        """
        self.graph.add_edge(from_node, to_node, feedback=feedback)
        return self

    def set_context(self, key: str, value: Any):
        """Set shared context value accessible to all nodes."""
        with self._lock:
            self._context[key] = value

    def get_context(self, key: str, default=None) -> Any:
        with self._lock:
            return self._context.get(key, default)

    def _get_ready_nodes(self, completed: Set[str], failed: Set[str]) -> List[str]:
        """Get nodes whose all non-feedback dependencies are completed."""
        ready = []
        for node_name in self.nodes:
            node = self.nodes[node_name]
            if node.status != NodeStatus.PENDING:
                continue
            # Check all incoming non-feedback edges
            deps_met = True
            for pred in self.graph.predecessors(node_name):
                edge_data = self.graph.edges[pred, node_name]
                if not edge_data.get("feedback", False):
                    if pred not in completed:
                        deps_met = False
                        break
            if deps_met:
                ready.append(node_name)
        return ready

    def _execute_node(self, node_name: str) -> bool:
        """Execute a single node. Returns True on success."""
        node = self.nodes[node_name]
        node.status = NodeStatus.RUNNING
        node.started_at = time.time()

        print(f"[DAG:{self.name}] Starting {node_name} ({node.role}/{node.model})")

        while node.retries <= node.retry_limit:
            try:
                if node.handler:
                    result = node.handler(node, self._context)
                    node.output = result
                    # Store output in shared context
                    self.set_context(f"{node_name}_output", result)
                else:
                    # No handler = dry-run / placeholder
                    node.output = f"[DRY-RUN] {node.description}"
                    self.set_context(f"{node_name}_output", node.output)

                node.status = NodeStatus.COMPLETED
                node.finished_at = time.time()
                print(f"[DAG:{self.name}] Completed {node_name} in {node.duration():.1f}s")
                return True

            except Exception as e:
                node.retries += 1
                node.error = str(e)
                if node.retries > node.retry_limit:
                    node.status = NodeStatus.FAILED
                    node.finished_at = time.time()
                    print(f"[DAG:{self.name}] FAILED {node_name}: {e}")
                    return False
                print(f"[DAG:{self.name}] Retry {node.retries}/{node.retry_limit} for {node_name}")
                time.sleep(2 ** node.retries)  # exponential backoff

        return False

    def run(self) -> Dict[str, Any]:
        """
        Execute the DAG. Returns execution summary.
        Independent nodes run in parallel via ThreadPoolExecutor.
        """
        # Validate DAG (ignore feedback edges for cycle detection)
        non_feedback_edges = [
            (u, v) for u, v, d in self.graph.edges(data=True)
            if not d.get("feedback", False)
        ]
        dag_check = nx.DiGraph()
        dag_check.add_edges_from(non_feedback_edges)
        if not nx.is_directed_acyclic_graph(dag_check):
            raise ValueError("DAG contains cycles in non-feedback edges")

        completed: Set[str] = set()
        failed: Set[str] = set()
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            in_flight: Dict[str, Any] = {}  # future -> node_name

            while True:
                # Submit ready nodes
                ready = self._get_ready_nodes(completed, failed)
                for node_name in ready:
                    if node_name not in in_flight.values():
                        future = executor.submit(self._execute_node, node_name)
                        in_flight[future] = node_name

                if not in_flight:
                    break

                # Wait for any to complete
                done_futures = []
                for future in list(in_flight.keys()):
                    if future.done():
                        done_futures.append(future)

                if not done_futures:
                    time.sleep(0.1)
                    continue

                for future in done_futures:
                    node_name = in_flight.pop(future)
                    success = future.result()
                    if success:
                        completed.add(node_name)
                    else:
                        failed.add(node_name)
                        # Mark downstream nodes as skipped
                        for successor in nx.descendants(self.graph, node_name):
                            if self.nodes[successor].status == NodeStatus.PENDING:
                                self.nodes[successor].status = NodeStatus.SKIPPED

        total_time = time.time() - start_time
        return self._build_summary(completed, failed, total_time)

    def _build_summary(self, completed: Set[str], failed: Set[str], total_time: float) -> Dict[str, Any]:
        return {
            "pipeline": self.name,
            "total_time": round(total_time, 2),
            "nodes": {
                name: {
                    "status": node.status.value,
                    "role": node.role,
                    "model": node.model,
                    "duration": round(node.duration(), 2),
                    "retries": node.retries,
                    "error": node.error or None,
                }
                for name, node in self.nodes.items()
            },
            "completed": list(completed),
            "failed": list(failed),
            "context_keys": list(self._context.keys()),
        }

    def visualize(self) -> str:
        """Return ASCII representation of the DAG."""
        lines = [f"Pipeline: {self.name}"]
        lines.append("=" * 40)
        try:
            # Remove feedback edges temporarily for visualization
            viz_graph = self.graph.copy()
            feedback = [(u, v) for u, v, d in viz_graph.edges(data=True) if d.get("feedback")]
            viz_graph.remove_edges_from(feedback)
            for layer in nx.topological_generations(viz_graph):
                layer_nodes = []
                for n in layer:
                    node = self.nodes.get(n)
                    status_icon = {
                        NodeStatus.PENDING: "○",
                        NodeStatus.RUNNING: "◉",
                        NodeStatus.COMPLETED: "✓",
                        NodeStatus.FAILED: "✗",
                        NodeStatus.SKIPPED: "⊘",
                    }.get(node.status if node else NodeStatus.PENDING, "?")
                    layer_nodes.append(f"{status_icon} {n}({node.model if node else '?'})")
                lines.append(" | ".join(layer_nodes))
                lines.append("  ↓")
            if feedback:
                lines.append(f"  ↻ feedback edges: {', '.join(f'{u}→{v}' for u, v in feedback)}")
        except Exception:
            lines.append("[unable to visualize]")
        return "\n".join(lines)
