const geoCache = new Map<string, string>();

function countryCodeToFlag(code: string): string {
  return [...code.toUpperCase()]
    .map((c) => String.fromCodePoint(c.charCodeAt(0) + 127397))
    .join("");
}

export async function getHostFlag(host: string): Promise<string> {
  if (geoCache.has(host)) return geoCache.get(host)!;

  try {
    const resp = await fetch(`http://ip-api.com/json/${host}?fields=countryCode`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!resp.ok) throw new Error("geo api error");
    const data = (await resp.json()) as { countryCode?: string };
    const flag = data.countryCode ? countryCodeToFlag(data.countryCode) : "🌐";
    geoCache.set(host, flag);
    return flag;
  } catch {
    geoCache.set(host, "🌐");
    return "🌐";
  }
}

export function buildConfigName(flag: string): string {
  return `${flag} ОСТАНЕТСЯ НА СВЯЗИ 🛜`;
}

export function rebuildUriWithName(rawUri: string, name: string): string {
  const hashIdx = rawUri.indexOf("#");
  const base = hashIdx >= 0 ? rawUri.slice(0, hashIdx) : rawUri;
  return `${base}#${encodeURIComponent(name)}`;
}
