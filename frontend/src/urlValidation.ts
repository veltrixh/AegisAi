const BLOCKED_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal']);

export interface TargetUrlCheck {
  valid: boolean;
  normalized: string;
  message: string;
}

export function checkTargetUrl(value: string): TargetUrlCheck {
  const input = value.trim();
  if (!input) {
    return { valid: false, normalized: '', message: 'Enter a target URL.' };
  }

  const candidate = /^https?:\/\//i.test(input) ? input : `http://${input}`;
  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, normalized: '', message: 'Enter a valid hostname or IP address.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, normalized: '', message: 'Only HTTP and HTTPS targets are supported.' };
  }

  if (!parsed.hostname) {
    return { valid: false, normalized: '', message: 'A hostname or IP address is required.' };
  }

  const isIpv4Address = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
  const isIpv6Address = parsed.hostname.includes(':');
  const isIpAddress = isIpv4Address || isIpv6Address;
  const isRecognizedHost = parsed.hostname === 'localhost' || isIpAddress || parsed.hostname.includes('.');
  if (!isRecognizedHost) {
    return { valid: false, normalized: '', message: 'Use a domain, localhost, or IP address.' };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, normalized: '', message: 'Embedded usernames and passwords are not allowed.' };
  }

  if (BLOCKED_HOSTS.has(parsed.hostname.toLowerCase())) {
    return { valid: false, normalized: '', message: 'Cloud metadata endpoints cannot be scanned.' };
  }

  return {
    valid: true,
    normalized: `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}${parsed.search}`,
    message: 'Target format is valid.'
  };
}