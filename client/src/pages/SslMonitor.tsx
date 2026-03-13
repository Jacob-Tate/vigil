import { useState } from "react";
import toast from "react-hot-toast";
import { SslTarget, SslTargetFormData } from "../types";
import { useSslTargets } from "../hooks/useSslTargets";
import {
  createSslTarget,
  updateSslTarget,
  deleteSslTarget,
  triggerSslCheck,
} from "../api/client";
import SslTargetCard from "../components/SslTargetCard";
import SslTargetForm from "../components/SslTargetForm";
import { useAuth } from "../hooks/useAuth";

type SslStatus = "valid" | "expiring" | "expired" | "error" | "pending";

function getStatus(target: SslTarget): SslStatus {
  const check = target.last_check;
  if (!check) return "pending";
  if (check.error) return "error";
  if (check.days_remaining === null) return "pending";
  if (check.days_remaining < 0) return "expired";
  if (check.days_remaining <= target.expiry_threshold_hours / 24) return "expiring";
  return "valid";
}

export default function SslMonitor() {
  const { targets, loading, error, refetch } = useSslTargets();
  const { isAdmin } = useAuth();
  const [showForm, setShowForm] = useState(false);
  const [editTarget, setEditTarget] = useState<SslTarget | null>(null);
  const [checkingIds, setCheckingIds] = useState<Set<number>>(new Set());

  const statusCounts = targets.reduce(
    (acc, t) => {
      acc[getStatus(t)]++;
      return acc;
    },
    { valid: 0, expiring: 0, expired: 0, error: 0, pending: 0 } as Record<SslStatus, number>
  );

  const handleSave = async (data: SslTargetFormData) => {
    if (editTarget) {
      await updateSslTarget(editTarget.id, data);
      toast.success("SSL target updated");
    } else {
      await createSslTarget(data);
      toast.success("SSL target added");
    }
    setShowForm(false);
    setEditTarget(null);
    await refetch();
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this SSL target?")) return;
    await deleteSslTarget(id);
    toast.success("SSL target deleted");
    await refetch();
  };

  const handleCheck = async (id: number) => {
    setCheckingIds((s) => new Set(s).add(id));
    try {
      await triggerSslCheck(id);
      toast.success("Check complete");
      await refetch();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Check failed");
    } finally {
      setCheckingIds((s) => {
        const next = new Set(s);
        next.delete(id);
        return next;
      });
    }
  };

  const handleEdit = (target: SslTarget) => {
    setEditTarget(target);
    setShowForm(true);
  };

  const handleClose = () => {
    setShowForm(false);
    setEditTarget(null);
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SSL Monitor</h1>
          <p className="text-sm text-gray-500 mt-0.5">Track SSL certificate health and expiry</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => { setEditTarget(null); setShowForm(true); }}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Target
          </button>
        )}
      </div>

      {/* Stats bar */}
      {targets.length > 0 && (
        <div className="flex gap-4 mb-6 flex-wrap">
          {statusCounts.valid > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-green-700">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              {statusCounts.valid} Valid
            </div>
          )}
          {statusCounts.expiring > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-amber-700">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              {statusCounts.expiring} Expiring
            </div>
          )}
          {statusCounts.expired > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-red-700">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              {statusCounts.expired} Expired
            </div>
          )}
          {statusCounts.error > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-red-700">
              <span className="w-2 h-2 rounded-full bg-red-400" />
              {statusCounts.error} Error
            </div>
          )}
          {statusCounts.pending > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-gray-500">
              <span className="w-2 h-2 rounded-full bg-gray-300" />
              {statusCounts.pending} Pending
            </div>
          )}
        </div>
      )}

      {/* Content */}
      {loading && (
        <div className="text-sm text-gray-400 py-8 text-center">Loading…</div>
      )}

      {error && (
        <div className="text-sm text-red-600 bg-red-50 rounded-xl p-4">{error}</div>
      )}

      {!loading && !error && targets.length === 0 && (
        <div className="text-center py-16 text-gray-400">
          <svg className="w-12 h-12 mx-auto mb-3 text-gray-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p className="text-sm font-medium">No SSL targets yet</p>
          <p className="text-xs mt-1">Add a domain to start monitoring its certificate.</p>
        </div>
      )}

      {!loading && targets.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {targets.map((target) => (
            <SslTargetCard
              key={target.id}
              target={target}
              onCheck={isAdmin ? handleCheck : undefined}
              onEdit={isAdmin ? handleEdit : undefined}
              onDelete={isAdmin ? handleDelete : undefined}
              checking={checkingIds.has(target.id)}
            />
          ))}
        </div>
      )}

      {showForm && isAdmin && (
        <SslTargetForm
          target={editTarget}
          onSave={handleSave}
          onClose={handleClose}
        />
      )}
    </div>
  );
}
