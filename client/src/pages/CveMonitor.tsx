import { useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { CveTargetWithStats, CveTargetFormData } from "../types";
import { useCveTargets } from "../hooks/useCveTargets";
import {
  createCveTarget,
  updateCveTarget,
  deleteCveTarget,
  triggerCveCheck,
} from "../api/client";
import NvdSyncPanel from "../components/NvdSyncPanel";
import KevSyncPanel from "../components/KevSyncPanel";
import CveTargetCard from "../components/CveTargetCard";
import CveTargetForm from "../components/CveTargetForm";
import { useAuth } from "../hooks/useAuth";

export default function CveMonitor() {
  const { targets, loading, error, refetch } = useCveTargets();
  const { isAdmin } = useAuth();
  const [showForm, setShowForm] = useState(false);
  const [editTarget, setEditTarget] = useState<CveTargetWithStats | null>(null);
  const [checkingIds, setCheckingIds] = useState<Set<number>>(new Set());

  const totalFindings = targets.reduce((s, t) => s + t.findings_count, 0);

  const handleSave = async (data: CveTargetFormData) => {
    if (editTarget) {
      await updateCveTarget(editTarget.id, data);
      toast.success("CVE target updated");
    } else {
      await createCveTarget(data);
      toast.success("CVE target added");
    }
    setShowForm(false);
    setEditTarget(null);
    await refetch();
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this CVE target?")) return;
    await deleteCveTarget(id);
    toast.success("CVE target deleted");
    await refetch();
  };

  const handleCheck = async (id: number) => {
    setCheckingIds((s) => new Set(s).add(id));
    try {
      await triggerCveCheck(id);
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

  const handleEdit = (target: CveTargetWithStats) => {
    setEditTarget(target);
    setShowForm(true);
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">CVE Monitor</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
            Track vulnerabilities for your technology stack
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/cve/browse?kev=true"
            className="border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 px-4 py-2 rounded-lg text-sm font-medium hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
          >
            Browse KEVs
          </Link>
          <Link
            to="/cve/browse"
            className="border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
          >
            Browse CVEs
          </Link>
          {isAdmin && (
            <button
              onClick={() => {
                setEditTarget(null);
                setShowForm(true);
              }}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 4v16m8-8H4"
                />
              </svg>
              Add Target
            </button>
          )}
        </div>
      </div>

      {/* NVD sync panel */}
      <NvdSyncPanel />
      <KevSyncPanel />

      {/* Stats bar */}
      {targets.length > 0 && (
        <div className="flex gap-4 mb-6 text-sm text-gray-600 dark:text-gray-400">
          <span>{targets.length} target{targets.length !== 1 ? "s" : ""}</span>
          {totalFindings > 0 && (
            <span className="text-orange-600 dark:text-orange-400">{totalFindings} total CVEs found</span>
          )}
        </div>
      )}

      {/* Content */}
      {loading && (
        <div className="text-sm text-gray-400 dark:text-gray-500 py-8 text-center">Loading…</div>
      )}

      {error && (
        <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-xl p-4">{error}</div>
      )}

      {!loading && !error && targets.length === 0 && (
        <div className="text-center py-16 text-gray-400 dark:text-gray-500">
          <svg
            className="w-12 h-12 mx-auto mb-3 text-gray-200 dark:text-gray-700"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
          <p className="text-sm font-medium">No CVE targets yet</p>
          <p className="text-xs mt-1">
            Add a product to start tracking its vulnerabilities.
          </p>
        </div>
      )}

      {!loading && targets.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {targets.map((target) => (
            <CveTargetCard
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
        <CveTargetForm
          target={editTarget}
          onSave={handleSave}
          onClose={() => {
            setShowForm(false);
            setEditTarget(null);
          }}
        />
      )}
    </div>
  );
}
