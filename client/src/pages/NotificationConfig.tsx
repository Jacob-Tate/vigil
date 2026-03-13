import { useState } from "react";
import toast from "react-hot-toast";
import { NotificationChannel } from "../types";
import {
  createNotification,
  updateNotification,
  deleteNotification,
  testNotification,
} from "../api/client";
import { useNotifications } from "../hooks/useNotifications";
import NotifierForm from "../components/NotifierForm";
import { Link } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

export default function NotificationConfig() {
  const { channels, types, loading, error, refresh } = useNotifications();
  const { isAdmin } = useAuth();
  const [editChannel, setEditChannel] = useState<NotificationChannel | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const handleSave = async (data: {
    type: string;
    label?: string;
    config: Record<string, unknown>;
    active?: boolean;
  }) => {
    if (editChannel) {
      await updateNotification(editChannel.id, { label: data.label, config: data.config, active: data.active });
      toast.success("Channel updated");
    } else {
      await createNotification(data);
      toast.success("Channel added");
    }
    await refresh();
  };

  const handleDelete = async (ch: NotificationChannel) => {
    if (!confirm(`Delete "${ch.label ?? ch.type}" channel?`)) return;
    try {
      await deleteNotification(ch.id);
      toast.success("Channel deleted");
      await refresh();
    } catch {
      toast.error("Failed to delete channel");
    }
  };

  const handleToggle = async (ch: NotificationChannel) => {
    try {
      await updateNotification(ch.id, { active: ch.active === 0 });
      await refresh();
    } catch {
      toast.error("Failed to update channel");
    }
  };

  const handleTest = async (ch: NotificationChannel) => {
    try {
      await testNotification(ch.id);
      toast.success("Test alert sent!");
    } catch {
      toast.error("Test alert failed");
    }
  };

  return (
    <div className="max-w-2xl mx-auto px-4 py-6">
      <div className="mb-6">
        <Link to="/" className="text-sm text-gray-400 dark:text-gray-500 hover:text-blue-600 mb-2 inline-block">
          ← Dashboard
        </Link>
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Notifications</h1>
          {isAdmin && (
            <button
              onClick={() => { setEditChannel(null); setShowAdd(true); }}
              disabled={loading || types.length === 0}
              className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              + Add channel
            </button>
          )}
        </div>
      </div>

      {loading && <p className="text-center py-8 text-gray-400 dark:text-gray-500">Loading…</p>}
      {error && <p className="text-red-500 text-sm">{error}</p>}

      {!loading && channels.length === 0 && (
        <div className="text-center py-16">
          <p className="text-gray-400 dark:text-gray-500 mb-4">No notification channels configured</p>
          {isAdmin && (
            <button
              onClick={() => { setEditChannel(null); setShowAdd(true); }}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Add your first channel
            </button>
          )}
        </div>
      )}

      <div className="flex flex-col gap-3">
        {channels.map((ch) => {
          const typeDef = types.find((t) => t.type === ch.type);
          return (
            <div
              key={ch.id}
              className={`bg-white dark:bg-gray-900 rounded-xl border p-4 flex items-center justify-between gap-4 ${
                ch.active ? "border-gray-200 dark:border-gray-700" : "border-gray-100 dark:border-gray-700 opacity-60"
              }`}
            >
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {ch.label ?? typeDef?.displayName ?? ch.type}
                </p>
                <p className="text-xs text-gray-400 dark:text-gray-500">{typeDef?.displayName ?? ch.type}</p>
              </div>
              {isAdmin && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => void handleTest(ch)}
                    className="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/50"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => { setEditChannel(ch); setShowAdd(true); }}
                    className="text-xs px-2 py-1 rounded bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => void handleToggle(ch)}
                    className={`text-xs px-2 py-1 rounded ${
                      ch.active
                        ? "bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 hover:bg-green-100"
                        : "bg-gray-50 dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                    }`}
                  >
                    {ch.active ? "Enabled" : "Disabled"}
                  </button>
                  <button
                    onClick={() => void handleDelete(ch)}
                    className="text-xs px-2 py-1 rounded bg-red-50 dark:bg-red-900/20 text-red-500 dark:text-red-400 hover:bg-red-100"
                  >
                    Delete
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {showAdd && isAdmin && (
        <NotifierForm
          types={types}
          channel={editChannel}
          onSave={handleSave}
          onClose={() => { setShowAdd(false); setEditChannel(null); }}
        />
      )}
    </div>
  );
}
