import { useState } from "react";
import toast from "react-hot-toast";
import { Server, ServerFormData } from "../types";
import { createServer, updateServer, deleteServer, triggerCheck } from "../api/client";
import { useServers } from "../hooks/useServers";
import { useAuth } from "../hooks/useAuth";
import ServerCard from "../components/ServerCard";
import ServerForm from "../components/ServerForm";

export default function Dashboard() {
  const { servers, loading, error, refresh } = useServers();
  const { isAdmin } = useAuth();
  const [editServer, setEditServer] = useState<Server | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const handleSave = async (data: ServerFormData) => {
    if (editServer) {
      await updateServer(editServer.id, data);
      toast.success("Server updated");
    } else {
      await createServer(data);
      toast.success("Server added");
    }
    await refresh();
  };

  const handleDelete = async (server: Server) => {
    if (!confirm(`Delete "${server.name}"? This will remove all check history.`)) return;
    try {
      await deleteServer(server.id);
      toast.success("Server deleted");
      await refresh();
    } catch {
      toast.error("Failed to delete server");
    }
  };

  const handleCheck = async (server: Server) => {
    try {
      await triggerCheck(server.id);
      toast.success(`Check triggered for ${server.name}`);
      await refresh();
    } catch {
      toast.error("Failed to trigger check");
    }
  };

  const upCount = servers.filter((s) => s.last_check?.is_up === 1).length;
  const downCount = servers.filter((s) => s.last_check !== null && s.last_check.is_up === 0).length;

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Monitor</h1>
          {servers.length > 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
              {upCount} up · {downCount} down · {servers.length - upCount - downCount} pending
            </p>
          )}
        </div>
        {isAdmin && (
          <button
            onClick={() => { setEditServer(null); setShowAdd(true); }}
            className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
          >
            + Add server
          </button>
        )}
      </div>

      {loading && (
        <div className="text-center py-16 text-gray-400">Loading…</div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-xl p-4 text-sm">{error}</div>
      )}

      {!loading && servers.length === 0 && (
        <div className="text-center py-16">
          <p className="text-gray-400 dark:text-gray-500 text-lg mb-4">No servers yet</p>
          {isAdmin && (
            <button
              onClick={() => { setEditServer(null); setShowAdd(true); }}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Add your first server
            </button>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {servers.map((server) => (
          <ServerCard
            key={server.id}
            server={server}
            onEdit={isAdmin ? (s) => { setEditServer(s); setShowAdd(true); } : undefined}
            onDelete={isAdmin ? (s) => void handleDelete(s) : undefined}
            onCheck={isAdmin ? (s) => void handleCheck(s) : undefined}
          />
        ))}
      </div>

      {showAdd && isAdmin && (
        <ServerForm
          server={editServer}
          onSave={handleSave}
          onClose={() => { setShowAdd(false); setEditServer(null); }}
        />
      )}
    </div>
  );
}
