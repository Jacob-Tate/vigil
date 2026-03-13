import { useState } from "react";
import { CveTarget, CveTargetFormData } from "../types";

interface Props {
  target: CveTarget | null;
  onSave: (data: CveTargetFormData) => Promise<void>;
  onClose: () => void;
}

export default function CveTargetForm({ target, onSave, onClose }: Props) {
  const [form, setForm] = useState<CveTargetFormData>({
    name: target?.name ?? "",
    product: target?.product ?? "",
    vendor: target?.vendor ?? null,
    version: target?.version ?? null,
    min_alert_cvss_score: target?.min_alert_cvss_score ?? 7.0,
    check_interval_seconds: target?.check_interval_seconds ?? 86400,
    active: target ? target.active === 1 : true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.product.trim()) {
      setError("Name and product are required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave({
        ...form,
        vendor: form.vendor?.trim() || null,
        version: form.version?.trim() || null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="px-6 pt-6 pb-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">
            {target ? "Edit CVE Target" : "Add CVE Target"}
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Matches CVEs using CPE — vendor:product:version format
          </p>
        </div>
        <form onSubmit={(e) => void handleSubmit(e)} className="px-6 py-4 space-y-4">
          {error && (
            <div className="text-sm text-red-600 bg-red-50 rounded-lg p-3">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. Moodle on example.com"
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Product <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={form.product}
                onChange={(e) => setForm({ ...form, product: e.target.value })}
                placeholder="e.g. moodle, nginx, php"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-400 mt-0.5">CPE product name</p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Vendor
              </label>
              <input
                type="text"
                value={form.vendor ?? ""}
                onChange={(e) =>
                  setForm({ ...form, vendor: e.target.value || null })
                }
                placeholder="same as product"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-400 mt-0.5">Optional</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Version
              </label>
              <input
                type="text"
                value={form.version ?? ""}
                onChange={(e) =>
                  setForm({ ...form, version: e.target.value || null })
                }
                placeholder="e.g. 4.5 (blank = any)"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Min Alert CVSS Score
              </label>
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={form.min_alert_cvss_score}
                onChange={(e) =>
                  setForm({ ...form, min_alert_cvss_score: parseFloat(e.target.value) })
                }
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-400 mt-0.5">Alert threshold (0–10)</p>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Check Interval
            </label>
            <select
              value={form.check_interval_seconds}
              onChange={(e) =>
                setForm({
                  ...form,
                  check_interval_seconds: parseInt(e.target.value, 10),
                })
              }
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={3600}>Every hour</option>
              <option value={21600}>Every 6 hours</option>
              <option value={43200}>Every 12 hours</option>
              <option value={86400}>Every 24 hours</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <input
              id="cve-active"
              type="checkbox"
              checked={form.active}
              onChange={(e) => setForm({ ...form, active: e.target.checked })}
              className="rounded"
            />
            <label htmlFor="cve-active" className="text-sm text-gray-700">
              Active monitoring
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : target ? "Save Changes" : "Add Target"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
