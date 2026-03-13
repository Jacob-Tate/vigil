import {
  Server,
  Check,
  ContentDiff,
  CheckStats,
  PaginatedChecks,
  NotificationChannel,
  NotifierTypeDef,
  ServerFormData,
  SslTarget,
  SslCheck,
  SslCheckStats,
  PaginatedSslChecks,
  SslTargetFormData,
  CveTarget,
  CveTargetWithStats,
  CveTargetFormData,
  CveFinding,
  PaginatedCveFindings,
  NvdSyncStatus,
  NvdCveDetail,
  PaginatedNvdCves,
  KevSyncState,
  VulnrichmentSyncState,
  CvelistSyncState,
  UserListItem,
  UserFormData,
  UserUpdateData,
} from "../types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (res.status === 401) {
    window.location.href = "/login";
    return new Promise<T>(() => undefined);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText })) as { error?: string };
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

// Servers
export const getServers = () => request<Server[]>("/servers");
export const getServer = (id: number) => request<Server>(`/servers/${id}`);
export const createServer = (data: ServerFormData) =>
  request<Server>("/servers", { method: "POST", body: JSON.stringify(data) });
export const updateServer = (id: number, data: Partial<ServerFormData>) =>
  request<Server>(`/servers/${id}`, { method: "PUT", body: JSON.stringify(data) });
export const deleteServer = (id: number) =>
  request<void>(`/servers/${id}`, { method: "DELETE" });
export const triggerCheck = (id: number) =>
  request<{ ok: boolean; check: Check | null }>(`/servers/${id}/check`, { method: "POST" });
export const resetBaseline = (id: number) =>
  request<{ ok: boolean; message: string }>(`/servers/${id}/reset-baseline`, { method: "POST" });

// Checks
export const getChecks = (serverId: number, page = 1, limit = 50) =>
  request<PaginatedChecks>(`/checks?serverId=${serverId}&page=${page}&limit=${limit}`);
export const getCheckStats = (serverId: number) =>
  request<CheckStats>(`/checks/stats/${serverId}`);

// Diffs
export const getDiffs = (serverId: number) =>
  request<ContentDiff[]>(`/diffs?serverId=${serverId}`);
export const getDiff = (id: number) =>
  request<ContentDiff>(`/diffs/${id}`);

// Notifications
export const getNotifications = () =>
  request<NotificationChannel[]>("/notifications");
export const getNotifierTypes = () =>
  request<NotifierTypeDef[]>("/notifications/types");
export const createNotification = (data: {
  type: string;
  label?: string;
  config: Record<string, unknown>;
  active?: boolean;
}) => request<NotificationChannel>("/notifications", { method: "POST", body: JSON.stringify(data) });
export const updateNotification = (
  id: number,
  data: { label?: string; config?: Record<string, unknown>; active?: boolean }
) =>
  request<NotificationChannel>(`/notifications/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
export const deleteNotification = (id: number) =>
  request<void>(`/notifications/${id}`, { method: "DELETE" });
export const testNotification = (id: number) =>
  request<{ ok: boolean }>(`/notifications/${id}/test`, { method: "POST" });

// SSL Targets
export const getSslTargets = () =>
  request<SslTarget[]>("/ssl/targets");
export const getSslTarget = (id: number) =>
  request<SslTarget>(`/ssl/targets/${id}`);
export const createSslTarget = (data: SslTargetFormData) =>
  request<SslTarget>("/ssl/targets", { method: "POST", body: JSON.stringify(data) });
export const updateSslTarget = (id: number, data: Partial<SslTargetFormData>) =>
  request<SslTarget>(`/ssl/targets/${id}`, { method: "PUT", body: JSON.stringify(data) });
export const deleteSslTarget = (id: number) =>
  request<void>(`/ssl/targets/${id}`, { method: "DELETE" });
export const triggerSslCheck = (id: number) =>
  request<{ ok: boolean; check: SslCheck | null }>(`/ssl/targets/${id}/check`, { method: "POST" });
export const getSslTargetCertUrl = (id: number) => `/api/ssl/targets/${id}/cert`;

// SSL Checks
export const getSslChecks = (targetId: number, page = 1, limit = 50) =>
  request<PaginatedSslChecks>(`/ssl/checks?targetId=${targetId}&page=${page}&limit=${limit}`);
export const getSslCheckStats = (targetId: number) =>
  request<SslCheckStats>(`/ssl/checks/stats/${targetId}`);
export const getSslCheck = (id: number) =>
  request<SslCheck>(`/ssl/checks/${id}`);

// NVD Sync
export const getNvdStatus = () =>
  request<NvdSyncStatus>("/nvd/status");
export const triggerNvdSync = () =>
  request<{ ok: boolean; message: string }>("/nvd/sync", { method: "POST" });
export const triggerNvdFeedSync = (feedName: string) =>
  request<{ ok: boolean; message: string }>(`/nvd/sync/${feedName}`, { method: "POST" });

// NVD Browse
export const searchNvdCves = (params: {
  q?: string;
  severity?: string;
  minScore?: number;
  from?: string;
  to?: string;
  kev?: boolean;
  page?: number;
  limit?: number;
}) => {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.severity) qs.set("severity", params.severity);
  if (params.minScore !== undefined) qs.set("minScore", String(params.minScore));
  if (params.from) qs.set("from", params.from);
  if (params.to) qs.set("to", params.to);
  if (params.kev) qs.set("kev", "true");
  qs.set("page", String(params.page ?? 1));
  qs.set("limit", String(params.limit ?? 50));
  return request<PaginatedNvdCves>(`/nvd/browse/search?${qs.toString()}`);
};
export const getNvdCve = (cveId: string) =>
  request<NvdCveDetail>(`/nvd/browse/cve/${encodeURIComponent(cveId)}`);

// CVE Targets
export const getCveTargets = () =>
  request<CveTargetWithStats[]>("/cve/targets");
export const getCveTarget = (id: number) =>
  request<CveTargetWithStats>(`/cve/targets/${id}`);
export const createCveTarget = (data: CveTargetFormData) =>
  request<CveTargetWithStats>("/cve/targets", { method: "POST", body: JSON.stringify(data) });
export const updateCveTarget = (id: number, data: Partial<CveTargetFormData>) =>
  request<CveTargetWithStats>(`/cve/targets/${id}`, { method: "PUT", body: JSON.stringify(data) });
export const deleteCveTarget = (id: number) =>
  request<void>(`/cve/targets/${id}`, { method: "DELETE" });
export const triggerCveCheck = (id: number) =>
  request<{ ok: boolean; target: CveTarget }>(`/cve/targets/${id}/check`, { method: "POST" });

// CVE Findings
export const getCveFindings = (
  targetId: number,
  page = 1,
  limit = 50,
  sortBy = "cvss_score",
  sortDir: "asc" | "desc" = "desc"
) =>
  request<PaginatedCveFindings>(
    `/cve/findings?targetId=${targetId}&page=${page}&limit=${limit}&sortBy=${sortBy}&sortDir=${sortDir}`
  );

// KEV Sync
export const getKevStatus = () =>
  request<KevSyncState>("/kev/status");
export const triggerKevSync = () =>
  request<{ ok: boolean; message: string }>("/kev/sync", { method: "POST" });

// Vulnrichment / SSVC Sync
export const getVulnrichmentStatus = () =>
  request<VulnrichmentSyncState>("/vulnrichment/status");
export const triggerVulnrichmentSync = () =>
  request<{ ok: boolean; message: string }>("/vulnrichment/sync", { method: "POST" });

// CVE Program cvelistV5 Sync
export const getCvelistStatus = () =>
  request<CvelistSyncState>("/cvelist/status");
export const triggerCvelistSync = () =>
  request<{ ok: boolean; message: string }>("/cvelist/sync", { method: "POST" });

// Users (admin only)
export const getUsers = () => request<UserListItem[]>("/users");
export const createUser = (data: UserFormData) =>
  request<UserListItem>("/users", { method: "POST", body: JSON.stringify(data) });
export const updateUser = (id: number, data: UserUpdateData) =>
  request<UserListItem>(`/users/${id}`, { method: "PUT", body: JSON.stringify(data) });
export const deleteUser = (id: number) =>
  request<void>(`/users/${id}`, { method: "DELETE" });

// Suppress unused import warnings until used
export type { CveFinding };
