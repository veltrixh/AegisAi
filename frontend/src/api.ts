import { ScanModel, FindingModel, ScanComparisonResult } from './types';

const API_BASE = '';

export async function launchScan(targetUrl: string, profile: string = 'standard'): Promise<ScanModel> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_url: targetUrl, profile })
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanModel> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error(`Scan ${scanId} not found`);
  return res.json();
}

export async function listScans(): Promise<ScanModel[]> {
  const res = await fetch(`${API_BASE}/api/scans`);
  if (!res.ok) return [];
  return res.json();
}

export async function cancelScan(scanId: string): Promise<void> {
  await fetch(`${API_BASE}/api/scans/${scanId}/cancel`, { method: 'POST' });
}

export async function compareScans(scanA: string, scanB: string): Promise<ScanComparisonResult> {
  const res = await fetch(`${API_BASE}/api/scans/compare?scan_a=${encodeURIComponent(scanA)}&scan_b=${encodeURIComponent(scanB)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function askAnalyst(question: string, scanId: string, findingId?: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/ai/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      question,
      scan_id: scanId,
      finding_id: findingId || null
    })
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function scanOpenApi(targetUrl: string, openapiSpec: string): Promise<ScanModel> {
  const res = await fetch(`${API_BASE}/api/scans/openapi`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_url: targetUrl, openapi_spec: openapiSpec, profile: 'api' })
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export function getReportDownloadUrl(scanId: string, format: string): string {
  return `${API_BASE}/api/scans/${scanId}/report?format=${format}`;
}
