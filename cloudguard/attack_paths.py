"""Resource graph and deterministic chained attack-path analysis."""
from dataclasses import dataclass

import networkx as nx
import plotly.graph_objects as go


@dataclass
class AttackPath:
    rank: int
    title: str
    nodes: list
    finding_ids: list
    severity: str
    rationale: str


def build_resource_graph(findings) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node("internet", kind="external")

    def add(source, target, rule):
        if graph.has_edge(source, target):
            graph.edges[source, target].setdefault("findings", []).append(rule)
        else:
            graph.add_edge(source, target, findings=[rule])

    for finding in findings:
        if finding.status != "FAIL":
            continue
        resource = finding.resource
        if finding.rule_id == "EC2-001":
            add("internet", resource, finding.rule_id)
        elif finding.rule_id == "EC2-002":
            for group_id in finding.evidence.get("security_groups", []):
                add(group_id, resource, "EC2-001")
            add(resource, "instance-role", finding.rule_id)
        elif finding.rule_id in {"S3-001", "S3-002", "S3-003"}:
            add("instance-role", resource, finding.rule_id)
        elif finding.rule_id in {"RDS-001", "RDS-002"}:
            add("instance-role", resource, finding.rule_id)
        elif finding.rule_id == "IAM-ESC-001":
            add("internet", resource, finding.rule_id)
    return graph


def find_attack_paths(findings) -> list[AttackPath]:
    graph = build_resource_graph(findings)
    paths = []
    for target in graph.nodes:
        if target == "internet":
            continue
        try:
            node_paths = nx.all_simple_paths(graph, "internet", target, cutoff=5)
        except nx.NetworkXNoPath:
            continue
        for nodes in node_paths:
            edge_findings = []
            for source, destination in zip(nodes, nodes[1:]):
                edge_findings.extend(graph.edges[source, destination]["findings"])
            if len(edge_findings) < 2:
                continue
            paths.append({
                "title": f"Internet to {target}",
                "nodes": nodes,
                "finding_ids": edge_findings,
                "severity": "CRITICAL" if any(rule in {"EC2-002", "S3-001", "RDS-001"} for rule in edge_findings) else "HIGH",
                "rationale": "A reachable management path combines with workload or data exposure.",
            })
    paths.sort(key=lambda path: (0 if path["severity"] == "CRITICAL" else 1, len(path["nodes"])))
    return [AttackPath(rank=index, **path) for index, path in enumerate(paths, 1)]


def graphviz_dot(findings) -> str:
    graph = build_resource_graph(findings)
    lines = ["digraph CloudGuard {"]
    for node in graph.nodes:
        safe = node.replace('"', "")
        lines.append(f'  "{safe}";')
    for source, target in graph.edges:
        lines.append(f'  "{source.replace(chr(34), "")}" -> "{target.replace(chr(34), "")}";')
    lines.append("}")
    return "\n".join(lines)


def plotly_figure(findings):
    """Return a deterministic interactive graph for the Streamlit dashboard."""
    graph = build_resource_graph(findings)
    if not graph.nodes:
        return go.Figure()
    positions = nx.spring_layout(graph, seed=7, k=1.5)
    edge_x, edge_y = [], []
    for source, target in graph.edges:
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    edges = go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line={"width": 1.5, "color": "#64748b"},
        hoverinfo="none",
    )
    labels = []
    colors = []
    for node in graph.nodes:
        labels.append(node)
        if node == "internet":
            colors.append("#dc2626")
        elif node == "instance-role":
            colors.append("#f59e0b")
        else:
            colors.append("#2563eb")
    node_x = [positions[node][0] for node in graph.nodes]
    node_y = [positions[node][1] for node in graph.nodes]
    nodes = go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        text=labels, textposition="bottom center",
        hovertemplate="%{text}<extra></extra>",
        marker={"size": 20, "color": colors, "line": {"width": 1, "color": "white"}},
    )
    figure = go.Figure(data=[edges, nodes])
    figure.update_layout(
        title="CloudGuard attack paths",
        showlegend=False,
        hovermode="closest",
        margin={"l": 10, "r": 10, "t": 45, "b": 10},
        xaxis={"visible": False},
        yaxis={"visible": False},
    )
    return figure
