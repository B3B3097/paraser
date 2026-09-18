import { useQuery, useMutation, type UseQueryOptions, type UseMutationOptions } from "@tanstack/react-query";

export type ListConfigsStatus = "working" | "failed" | "unchecked";
export type ListConfigsCheckLevel = "tcp" | "tls" | "http";

export interface ConfigItem {
  id: number;
  uuid: string;
  host: string;
  port: number;
  name: string;
  network: string | null;
  security: string | null;
  sni: string | null;
  path: string | null;
  flow: string | null;
  sourceId: number | null;
  rawUri: string;
  tcpStatus: "ok" | "fail" | null;
  tlsStatus: "ok" | "fail" | null;
  httpStatus: "ok" | "fail" | null;
  latencyMs: number | null;
  checkedAt: string | null;
  createdAt: string;
}

export interface ConfigStats {
  total: number;
  unchecked: number;
  tcpOk: number;
  tlsOk: number;
  httpOk: number;
  failed: number;
}

export interface CheckerStatus {
  running: boolean;
  level: string | null;
  total: number;
  checked: number;
  working: number;
  failed: number;
  startedAt: string | null;
}

export interface SourceItem {
  id: number;
  name: string;
  url: string;
  type: string;
  enabled: boolean;
  lastFetchedAt: string | null;
  configCount: number;
  createdAt: string;
}

export interface ExportResult {
  format: string;
  count: number;
  content: string;
}

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) {
    let errorMsg = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      if (data.error) errorMsg = data.error;
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

// Config Stats
export function getGetConfigStatsQueryKey() {
  return ["/api/configs/stats"];
}

export function useGetConfigStats(options?: {
  query?: Partial<UseQueryOptions<ConfigStats, Error>>;
}) {
  return useQuery<ConfigStats, Error>({
    queryKey: options?.query?.queryKey ?? getGetConfigStatsQueryKey(),
    queryFn: () => apiFetch<ConfigStats>("/api/configs/stats"),
    ...options?.query,
  });
}

// Checker Status
export function getGetCheckerStatusQueryKey() {
  return ["/api/checker/status"];
}

export function useGetCheckerStatus(options?: {
  query?: Partial<UseQueryOptions<CheckerStatus, Error>>;
}) {
  return useQuery<CheckerStatus, Error>({
    queryKey: options?.query?.queryKey ?? getGetCheckerStatusQueryKey(),
    queryFn: () => apiFetch<CheckerStatus>("/api/checker/status"),
    ...options?.query,
  });
}

// Start Check
export function useCheckConfigs(options?: {
  mutation?: UseMutationOptions<
    CheckerStatus,
    Error,
    { data: { level: string; concurrency?: number; timeoutMs?: number; configIds?: number[] } }
  >;
}) {
  return useMutation<
    CheckerStatus,
    Error,
    { data: { level: string; concurrency?: number; timeoutMs?: number; configIds?: number[] } }
  >({
    mutationFn: (variables) =>
      apiFetch<CheckerStatus>("/api/checker/check", {
        method: "POST",
        body: JSON.stringify(variables.data),
      }),
    ...options?.mutation,
  });
}

// List Configs
export function getListConfigsQueryKey(params?: {
  status?: string;
  checkLevel?: string;
}) {
  return ["/api/configs", params];
}

export function useListConfigs(
  params?: { status?: string; checkLevel?: string },
  options?: { query?: Partial<UseQueryOptions<ConfigItem[], Error>> }
) {
  const queryParams = new URLSearchParams();
  if (params?.status) queryParams.set("status", params.status);
  if (params?.checkLevel) queryParams.set("checkLevel", params.checkLevel);
  const qs = queryParams.toString();
  const url = `/api/configs${qs ? `?${qs}` : ""}`;

  return useQuery<ConfigItem[], Error>({
    queryKey: options?.query?.queryKey ?? getListConfigsQueryKey(params),
    queryFn: () => apiFetch<ConfigItem[]>(url),
    ...options?.query,
  });
}

// Clear Configs
export function useClearConfigs() {
  return useMutation<void, Error, void>({
    mutationFn: () =>
      apiFetch<void>("/api/configs", {
        method: "DELETE",
      }),
  });
}

// Export Configs
export function useExportConfigs(options?: {
  mutation?: UseMutationOptions<
    ExportResult,
    Error,
    { data: { format: string; level: string; limit?: number } }
  >;
}) {
  return useMutation<
    ExportResult,
    Error,
    { data: { format: string; level: string; limit?: number } }
  >({
    mutationFn: (variables) =>
      apiFetch<ExportResult>("/api/export", {
        method: "POST",
        body: JSON.stringify(variables.data),
      }),
    ...options?.mutation,
  });
}

// List Sources
export function getListSourcesQueryKey() {
  return ["/api/sources"];
}

export function useListSources(options?: {
  query?: Partial<UseQueryOptions<SourceItem[], Error>>;
}) {
  return useQuery<SourceItem[], Error>({
    queryKey: options?.query?.queryKey ?? getListSourcesQueryKey(),
    queryFn: () => apiFetch<SourceItem[]>("/api/sources"),
    ...options?.query,
  });
}

// Create Source
export function useCreateSource() {
  return useMutation<
    SourceItem,
    Error,
    { data: { name: string; url: string; type: string } }
  >({
    mutationFn: (variables) =>
      apiFetch<SourceItem>("/api/sources", {
        method: "POST",
        body: JSON.stringify(variables.data),
      }),
  });
}

// Delete Source
export function useDeleteSource() {
  return useMutation<void, Error, { id: number }>({
    mutationFn: (variables) =>
      apiFetch<void>(`/api/sources/${variables.id}`, {
        method: "DELETE",
      }),
  });
}

// Fetch Source
export function useFetchSource() {
  return useMutation<any, Error, { id: number }>({
    mutationFn: (variables) =>
      apiFetch<any>(`/api/sources/${variables.id}/fetch`, {
        method: "POST",
      }),
  });
}

// Fetch All Sources
export function useFetchAllSources() {
  return useMutation<any, Error, void>({
    mutationFn: () =>
      apiFetch<any>("/api/sources/fetch-all", {
        method: "POST",
      }),
  });
}
