import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import { formatDistanceToNow } from "date-fns";
import { UserListItem, UserFormData, UserUpdateData, UserRole } from "../types";
import { getUsers, createUser, updateUser, deleteUser } from "../api/client";
import { useAuth } from "../hooks/useAuth";

function useUsers() {
  const [users, setUsers] = useState<UserListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setUsers(await getUsers());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  return { users, loading, error, refetch: load };
}

interface FormState {
  username: string;
  password: string;
  role: UserRole;
}

interface UserFormProps {
  initial?: UserListItem;
  onSave: (data: FormState) => Promise<void>;
  onClose: () => void;
}

function UserForm({ initial, onSave, onClose }: UserFormProps) {
  const [form, setForm] = useState<FormState>({
    username: initial?.username ?? "",
    password: "",
    role: initial?.role ?? "viewer",
  });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const isEdit = !!initial;

  useEffect(() => {
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = ""; };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isEdit && form.password.length < 8) {
      setErr("Password must be at least 8 characters");
      return;
    }
    if (isEdit && form.password && form.password.length < 8) {
      setErr("Password must be at least 8 characters");
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      await onSave(form);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
        <div className="px-6 py-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900 dark:text-white">{isEdit ? "Edit user" : "Add user"}</h2>
          <button onClick={onClose} className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="px-6 py-4 space-y-4">
          {err && (
            <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg px-3 py-2">{err}</div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
            <input
              type="text"
              value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              required
              className="w-full border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="username"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Password{isEdit && <span className="text-gray-400 dark:text-gray-500 font-normal"> (leave blank to keep current)</span>}
            </label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              required={!isEdit}
              minLength={isEdit ? undefined : 8}
              className="w-full border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder={isEdit ? "••••••••" : "min 8 characters"}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Role</label>
            <select
              value={form.role}
              onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as UserRole }))}
              className="w-full border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            >
              <option value="viewer">Viewer — read-only access</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm rounded-lg border border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : isEdit ? "Save changes" : "Create user"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function UsersPage() {
  const { user: currentUser } = useAuth();
  const { users, loading, error, refetch } = useUsers();
  const [showForm, setShowForm] = useState(false);
  const [editTarget, setEditTarget] = useState<UserListItem | null>(null);

  const handleCreate = async (data: FormState) => {
    const payload: UserFormData = { username: data.username, password: data.password, role: data.role };
    await createUser(payload);
    toast.success("User created");
    setShowForm(false);
    await refetch();
  };

  const handleUpdate = async (data: FormState) => {
    if (!editTarget) return;
    const payload: UserUpdateData = { username: data.username, role: data.role };
    if (data.password) payload.password = data.password;
    await updateUser(editTarget.id, payload);
    toast.success("User updated");
    setShowForm(false);
    setEditTarget(null);
    await refetch();
  };

  const handleDelete = async (u: UserListItem) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    try {
      await deleteUser(u.id);
      toast.success("User deleted");
      await refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Delete failed");
    }
  };

  const openEdit = (u: UserListItem) => {
    setEditTarget(u);
    setShowForm(true);
  };

  const openCreate = () => {
    setEditTarget(null);
    setShowForm(true);
  };

  const roleLabel = (role: UserRole) =>
    role === "admin" ? (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-50 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400">
        Admin
      </span>
    ) : (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
        Viewer
      </span>
    );

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Users</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">Manage who can access Vigil</p>
        </div>
        <button
          onClick={openCreate}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add user
        </button>
      </div>

      {loading && <div className="text-sm text-gray-400 dark:text-gray-500 py-8 text-center">Loading…</div>}
      {error && <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-xl p-4">{error}</div>}

      {!loading && !error && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 dark:border-gray-700 text-left text-xs text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Role</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50 dark:divide-gray-700">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                  <td className="px-4 py-3 font-medium text-gray-900 dark:text-white">
                    {u.username}
                    {u.id === currentUser?.id && (
                      <span className="ml-2 text-xs text-gray-400 dark:text-gray-500">(you)</span>
                    )}
                  </td>
                  <td className="px-4 py-3">{roleLabel(u.role)}</td>
                  <td className="px-4 py-3 text-gray-400 dark:text-gray-500 text-xs">
                    {formatDistanceToNow(new Date(u.created_at), { addSuffix: true })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => openEdit(u)}
                        className="text-xs px-2 py-1 rounded bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                      >
                        Edit
                      </button>
                      {u.id !== currentUser?.id && (
                        <button
                          onClick={() => void handleDelete(u)}
                          className="text-xs px-2 py-1 rounded bg-red-50 dark:bg-red-900/20 text-red-500 dark:text-red-400 hover:bg-red-100"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-gray-400 dark:text-gray-500">
                    No users found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showForm && (
        <UserForm
          initial={editTarget ?? undefined}
          onSave={editTarget ? handleUpdate : handleCreate}
          onClose={() => { setShowForm(false); setEditTarget(null); }}
        />
      )}
    </div>
  );
}
