import uuid
from typing import List, Dict, Any
from urllib.parse import urlparse
from backend.models.finding import FindingModel
from backend.models.attack_path import GraphNode, GraphEdge, AttackChain, AttackGraphModel
from backend.utils.logger import logger

class AttackPathEngine:
    """
    Constructs deterministic directed attack graphs from verified findings.
    Traces threat path from Internet entrypoint through endpoints and parameters,
    into exploited vulnerabilities, and down to compromised assets.
    """

    @classmethod
    def generate(cls, target_url: str, findings: List[FindingModel]) -> AttackGraphModel:
        parsed = urlparse(target_url)
        hostname = parsed.netloc or target_url

        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        chains: List[AttackChain] = []
        existing_node_ids = set()

        def add_node(node: GraphNode):
            if node.id not in existing_node_ids:
                nodes.append(node)
                existing_node_ids.add(node.id)

        def add_edge(src: str, dst: str, rel: str, weight: float = 1.0):
            edge_id = f"e_{src}_{dst}"
            edges.append(GraphEdge(
                id=edge_id,
                source=src,
                target=dst,
                label=rel,
                relationship=rel,
                weight=weight
            ))

        # Root Node: Untrusted External Threat Actor
        threat_actor_id = "node_internet"
        add_node(GraphNode(
            id=threat_actor_id,
            label="Internet Threat Actor",
            type="entrypoint",
            details={"description": "External unauthenticated attacker transmitting HTTP/HTTPS requests"}
        ))

        # Perimeter Node: Target Web Application
        target_app_id = "node_webapp"
        add_node(GraphNode(
            id=target_app_id,
            label=f"Web Application ({hostname})",
            type="perimeter",
            details={"host": hostname, "scheme": parsed.scheme or "http"}
        ))
        add_edge(threat_actor_id, target_app_id, "transmits_traffic_to", 1.0)

        max_risk = 0.0

        for f in findings:
            if f.risk_score > max_risk:
                max_risk = f.risk_score

            f_parsed = urlparse(f.target)
            endpoint_path = f_parsed.path or "/"
            endpoint_id = f"ep_{abs(hash(f.target)) % 100000}"

            # Endpoint Node
            add_node(GraphNode(
                id=endpoint_id,
                label=f"Endpoint: {endpoint_path}",
                type="endpoint",
                details={"full_url": f.target, "method": f.method}
            ))
            add_edge(target_app_id, endpoint_id, "routes_request_to", 1.0)

            # Parameter Vector Node (if parameter exists)
            vuln_parent_id = endpoint_id
            if f.parameter and f.parameter != "HTTP Response Headers":
                param_id = f"param_{abs(hash(f.target + str(f.parameter))) % 100000}"
                add_node(GraphNode(
                    id=param_id,
                    label=f"Input Param: '{f.parameter}'",
                    type="vector",
                    details={"parameter_name": f.parameter, "method": f.method}
                ))
                add_edge(endpoint_id, param_id, "accepts_input", 1.0)
                vuln_parent_id = param_id

            # Vulnerability Node
            vuln_node_id = f"vuln_{f.finding_id}"
            add_node(GraphNode(
                id=vuln_node_id,
                label=f"{f.type} ({f.severity})",
                type="vulnerability",
                finding_id=f.finding_id,
                severity=f.severity,
                risk_score=f.risk_score,
                confidence=f.confidence,
                details={
                    "title": f.title,
                    "target": f.target,
                    "cwe": f.cwe.get("id"),
                    "owasp": f.owasp.get("id"),
                    "confidence": f.confidence,
                    "validation_status": f.validation_status,
                    "evidence_snippet": f.evidence.response.snippet if f.evidence and f.evidence.response else "",
                    "diff_summary": f.evidence.diff_summary if f.evidence else ""
                }
            ))
            add_edge(vuln_parent_id, vuln_node_id, "triggers_flaw", f.risk_score / 10.0)

            # Impact / Asset Compromise Node
            asset_info = cls._determine_compromised_asset(f)
            asset_id = asset_info["id"]
            add_node(GraphNode(
                id=asset_id,
                label=asset_info["label"],
                type="asset",
                severity=f.severity,
                details={"impact": asset_info["impact"]}
            ))
            add_edge(vuln_node_id, asset_id, asset_info["edge_label"], f.risk_score / 10.0)

            # Formulate Attack Chain
            chain_path = [threat_actor_id, target_app_id, endpoint_id]
            if vuln_parent_id != endpoint_id:
                chain_path.append(vuln_parent_id)
            chain_path.extend([vuln_node_id, asset_id])

            chains.append(AttackChain(
                chain_id=f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
                name=f"Compromise via {f.type} on {endpoint_path}",
                description=f"Path exploiting {f.type} in {f.parameter or 'endpoint'} resulting in {asset_info['label']}",
                path_nodes=chain_path,
                cumulative_risk=f.risk_score,
                likelihood=round(f.confidence / 100.0, 2),
                impact_level=f.severity
            ))

        logger.info(f"Attack graph created: {len(nodes)} nodes, {len(edges)} edges, {len(chains)} chains.")
        return AttackGraphModel(
            nodes=nodes,
            edges=edges,
            risk=round(max_risk, 1),
            chains=chains
        )

    @staticmethod
    def _determine_compromised_asset(finding: FindingModel) -> Dict[str, str]:
        ftype = finding.type.lower()
        if "sql" in ftype:
            return {
                "id": "asset_database",
                "label": "Relational Database Tier",
                "edge_label": "unauthorized_data_exfiltration",
                "impact": "Direct extraction or manipulation of database tables and schema records."
            }
        elif "xss" in ftype:
            return {
                "id": "asset_browser_session",
                "label": "Client Browser Session",
                "edge_label": "executes_script_in_client",
                "impact": "Execution of hostile script leading to session hijacking or credential phishing."
            }
        elif "csrf" in ftype:
            return {
                "id": "asset_account_state",
                "label": "User Account & Actions",
                "edge_label": "executes_state_changing_actions",
                "impact": "Unauthorized modification of user profile, passwords, or transaction records."
            }
        elif "ssrf" in ftype:
            return {
                "id": "asset_internal_network",
                "label": "Internal Cloud / Network Assets",
                "edge_label": "pivots_to_internal_services",
                "impact": "Extraction of IAM instance metadata tokens or unauthenticated internal microservices."
            }
        elif "api" in ftype:
            return {
                "id": "asset_api_backend",
                "label": "Backend Application Data",
                "edge_label": "unauthorized_object_access",
                "impact": "Direct object reference and API model enumeration."
            }
        else:
            return {
                "id": "asset_server_config",
                "label": "Server & Transport Security",
                "edge_label": "degrades_defense_in_depth",
                "impact": "Weakened perimeter and client defense-in-depth controls."
            }
