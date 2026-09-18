export interface ParsedVless {
  uuid: string;
  host: string;
  port: number;
  name: string;
  network: string | null;
  security: string | null;
  sni: string | null;
  path: string | null;
  flow: string | null;
  rawUri: string;
}

export function parseVlessUri(rawUri: string): ParsedVless | null {
  const trimmed = rawUri.trim();
  if (!trimmed.startsWith("vless://")) return null;

  try {
    const afterScheme = trimmed.slice(8);
    const atIdx = afterScheme.indexOf("@");
    if (atIdx === -1) return null;

    const uuid = afterScheme.slice(0, atIdx);
    const rest = afterScheme.slice(atIdx + 1);

    const hashIdx = rest.indexOf("#");
    const mainPart = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
    const namePart = hashIdx >= 0 ? decodeURIComponent(rest.slice(hashIdx + 1)) : "";

    const qIdx = mainPart.indexOf("?");
    const hostPortPart = qIdx >= 0 ? mainPart.slice(0, qIdx) : mainPart;
    const queryPart = qIdx >= 0 ? mainPart.slice(qIdx + 1) : "";

    let host: string;
    let port: number;

    if (hostPortPart.startsWith("[")) {
      const closeBracket = hostPortPart.indexOf("]");
      if (closeBracket === -1) return null;
      host = hostPortPart.slice(1, closeBracket);
      const colonAfter = hostPortPart.indexOf(":", closeBracket);
      port = colonAfter >= 0 ? parseInt(hostPortPart.slice(colonAfter + 1), 10) : 443;
    } else {
      const colonIdx = hostPortPart.lastIndexOf(":");
      if (colonIdx === -1) {
        host = hostPortPart;
        port = 443;
      } else {
        host = hostPortPart.slice(0, colonIdx);
        port = parseInt(hostPortPart.slice(colonIdx + 1), 10);
      }
    }

    if (!host || isNaN(port) || port <= 0 || port > 65535) return null;

    const params = new URLSearchParams(queryPart);
    const network = params.get("type") || null;
    const security = params.get("security") || null;
    const sni = params.get("sni") || params.get("host") || null;
    const path = params.get("path") || null;
    const flow = params.get("flow") || null;

    return {
      uuid,
      host,
      port,
      name: namePart || `${host}:${port}`,
      network,
      security,
      sni,
      path,
      flow,
      rawUri: trimmed,
    };
  } catch {
    return null;
  }
}

export function tryDecodeBase64(text: string): string {
  const trimmed = text.trim();
  if (trimmed.startsWith("vless://") || trimmed.includes("vless://")) {
    return text;
  }

  try {
    const cleaned = trimmed.replace(/\s+/g, "");
    const decoded = Buffer.from(cleaned, "base64").toString("utf-8");
    if (decoded.includes("vless://")) {
      return decoded;
    }
  } catch {
    // not base64
  }

  return text;
}

export function extractVlessFromText(text: string): ParsedVless[] {
  const lines = text.split(/[\r\n]+/);
  const results: ParsedVless[] = [];
  const seenUris = new Set<string>();

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("vless://")) continue;
    if (seenUris.has(trimmed)) continue;
    seenUris.add(trimmed);

    const parsed = parseVlessUri(trimmed);
    if (parsed) {
      results.push(parsed);
    }
  }

  return results;
}
