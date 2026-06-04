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

export function parseVlessUri(uri: string): ParsedVless | null {
  try {
    const trimmed = uri.trim();
    if (!trimmed.startsWith("vless://")) return null;

    const withoutScheme = trimmed.slice("vless://".length);
    const hashIdx = withoutScheme.indexOf("#");
    const name = hashIdx >= 0 ? decodeURIComponent(withoutScheme.slice(hashIdx + 1)) : "";
    const mainPart = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;

    const atIdx = mainPart.indexOf("@");
    if (atIdx < 0) return null;

    const uuid = mainPart.slice(0, atIdx);
    const rest = mainPart.slice(atIdx + 1);

    const qIdx = rest.indexOf("?");
    const hostPort = qIdx >= 0 ? rest.slice(0, qIdx) : rest;
    const queryStr = qIdx >= 0 ? rest.slice(qIdx + 1) : "";

    let host: string;
    let port: number;

    if (hostPort.startsWith("[")) {
      const closeBracket = hostPort.indexOf("]");
      if (closeBracket < 0) return null;
      host = hostPort.slice(1, closeBracket);
      const portPart = hostPort.slice(closeBracket + 1);
      port = parseInt(portPart.startsWith(":") ? portPart.slice(1) : portPart, 10);
    } else {
      const lastColon = hostPort.lastIndexOf(":");
      if (lastColon < 0) return null;
      host = hostPort.slice(0, lastColon);
      port = parseInt(hostPort.slice(lastColon + 1), 10);
    }

    if (!host || isNaN(port) || port <= 0 || port > 65535) return null;
    if (!uuid || uuid.length < 10) return null;

    const params = new URLSearchParams(queryStr);

    return {
      uuid,
      host,
      port,
      name,
      network: params.get("type") || params.get("network") || null,
      security: params.get("security") || params.get("tls") || null,
      sni: params.get("sni") || null,
      path: params.get("path") || null,
      flow: params.get("flow") || null,
      rawUri: trimmed,
    };
  } catch {
    return null;
  }
}

export function extractVlessFromText(text: string): ParsedVless[] {
  const results: ParsedVless[] = [];
  const seen = new Set<string>();

  const lines = text.split(/[\r\n\s]+/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("vless://")) continue;
    const parsed = parseVlessUri(trimmed);
    if (parsed) {
      const key = `${parsed.uuid}@${parsed.host}:${parsed.port}`;
      if (!seen.has(key)) {
        seen.add(key);
        results.push(parsed);
      }
    }
  }

  return results;
}

export function tryDecodeBase64(text: string): string {
  try {
    const decoded = Buffer.from(text.trim(), "base64").toString("utf-8");
    if (decoded.includes("vless://") || decoded.includes("vmess://") || decoded.includes("trojan://")) {
      return decoded;
    }
    return text;
  } catch {
    return text;
  }
}
