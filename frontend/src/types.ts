export interface RequestEvidence {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
  parameters: Record<string, any>;
}

export interface ResponseEvidence {
  status_code: number;
  response_time_ms: number;
  content_length: number;
  snippet: string;
  headers: Record<string, string>;
}

export interface EvidenceModel {
  baseline_response_length: number;
  test_response_length: number;
  length_diff: number;
  status_code_changed: boolean;
  baseline_status_code: number;
  test_status_code: number;
  response_time_changed: boolean;
  baseline_time_ms: number;
  test_time_ms: number;
  error_signature: string | null;
  payload_category: string;
  payloads_tested: number;
  successful_payloads: number;
  reproducible: boolean;
  reproduction_count: number;
  detection_rule: string;
  behavioral_changes: Record<string, any>;
  request?: RequestEvidence;
  response?: ResponseEvidence;
  diff_summary?: string;
}

export interface FindingModel {
  finding_id: string;
  scan_id: string;
  type: string;
  title: string;
  target: string;
  parameter: string | null;
  method: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  risk_score: number;
  cvss: number;
  cvss_vector: string;
  confidence: number;
  confidence_factors: Record<string, number>;
  validation_status: 'Confirmed' | 'Likely' | 'Suspicious' | 'Potential False Positive';
  owasp: { id: string; name: string };
  cwe: { id: string; name: string };
  evidence: EvidenceModel;
  ai_explanation?: {
    why_detected: string;
    evidence_factors: Record<string, number>;
    confidence_narrative: string;
    detection_logic: string;
    observed_behavior: Record<string, any>;
    impact_assessment: string;
    recommended_action: string;
  };
  remediation?: {
    problem: string;
    recommendation: string;
    verification: string;
    code_examples: Record<string, string>;
  };
  created_at: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'entrypoint' | 'perimeter' | 'endpoint' | 'vector' | 'vulnerability' | 'asset';
  finding_id?: string;
  severity?: string;
  risk_score?: number;
  confidence?: number;
  details: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  relationship: string;
  weight: number;
}

export interface AttackChain {
  chain_id: string;
  name: string;
  description: string;
  path_nodes: string[];
  cumulative_risk: number;
  likelihood: number;
  impact_level: string;
}

export interface AttackGraphModel {
  nodes: GraphNode[];
  edges: GraphEdge[];
  risk: number;
  chains: AttackChain[];
}

export interface VulnerabilityCorrelation {
  correlation_id: string;
  relationship_type: string;
  findings_involved: string[];
  confidence: number;
  reason: string;
  compounded_risk_score: number;
}

export interface ScanSummary {
  total_findings: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  security_score: number;
  top_risks: Array<any>;
}

export interface ScanModel {
  id: string;
  target_url: string;
  profile: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  current_phase: string;
  created_at: string;
  completed_at?: string;
  duration_seconds: number;
  config: {
    target_url: string;
    profile: string;
    max_concurrency: number;
    rate_limit: number;
    timeout: number;
  };
  summary: ScanSummary;
  findings: FindingModel[];
  correlations: VulnerabilityCorrelation[];
  attack_graph: AttackGraphModel;
  error_message?: string;
}

export interface ScanComparisonResult {
  base_scan_id: string;
  target_scan_id: string;
  new_findings: FindingModel[];
  fixed_findings: FindingModel[];
  unchanged_findings: FindingModel[];
  regressed_findings: FindingModel[];
  score_before: number;
  score_after: number;
  score_improvement: number;
  summary: Record<string, number>;
}
