import {
  Server,
  Check,
  ContentDiff,
  CheckStats,
  PaginatedChecks,
  NotificationChannel,
  NotifierTypeDef,
  ServerFormData,
} from "../types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
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
