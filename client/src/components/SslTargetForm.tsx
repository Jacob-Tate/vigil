import { useState, useEffect } from "react";
import { SslTarget, SslTargetFormData } from "../types";

interface Props {
  target?: SslTarget | null;
  onSave: (data: SslTargetFormData) => Promise<void>;
  onClose: () => void;
}

const THRESHOLD_PRESETS = [
  { label: "1h", hours: 1 },
  { label: "10h", hours: 10 },
  { label: "1d", hours: 24 },
  { label: "7d", hours: 168 },
];

function parseHostPort(input: string): { host: string; port: number } {
  // Strip protocol
  const stripped = input.replace(/^https?:\/\//i, "");
  // Split host:port
  const colonIdx = stripped.lastIndexOf(":");
  if (colonIdx > -1) {
    const portNum = parseInt(stripped.slice(colonIdx + 1), 10);
    if (!isNaN(portNum)) {
      return { host: stripped.slice(0, colonIdx).split("/")[0] ?? stripped.slice(0, colonIdx), port: portNum };
    }
  }
  return { host: stripped.split("/")[0] ?? stripped, port: 443 };
}

export default function SslTargetForm({ target, onSave, onClose }: Props) {
  const [form, setForm] = useState<SslTargetFormData>({
    name: "",
    host: "",
    port: 443,
    check_interval_seconds: 3600,
    expiry_threshold_hours: 168,
    active: true,
  });
  const [urlInput, setUrlInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [customThreshold, setCustomThreshold] = useState(false);

  useEffect(() => {
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = ""; };
  }, []);

  useEffect(() => {
    if (target) {
      setForm({
        name: target.name,
        host: target.host,
        port: target.port,
        check_interval_seconds: target.check_interval_seconds,
        expiry_threshold_hours: target.expiry_threshold_hours,
        active: target.active === 1,
      });
      setUrlInput(`${target.host}:${target.port}`);
      const isPreset = THRESHOLD_PRESETS.some((p) => p.hours === target.expiry_threshold_hours);
      setCustomThreshold(!isPreset);
    }
  }, [target]);

  const handleUrlBlur = () => {
    if (!urlInput.trim()) return;
    const { host, port } = parseHostPort(urlInput.trim());
    setForm((f) => ({ ...f, host, port }));
    if (!form.name) {
      setForm((f) => ({ ...f, name: host }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSave(form);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const isPresetActive = (hours: number) =>
    !customThreshold && form.expiry_threshold_hours === hours;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {target ? "Edit SSL Target" : "Add SSL Target"}
          </h2>
        </div>

        <form onSubmit={(e) => { void handleSubmit(e); }} className="px-6 py-5 space-y-4">
          {/* URL / Host input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              URL or Host
            </label>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onBlur={handleUrlBlur}
              placeholder="example.com or https://example.com or example.com:8443"
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
            />
            <div className="flex gap-2 mt-1.5">
              <div className="flex-1">
                <label className="text-xs text-gray-500 dark:text-gray-400">Host</label>
                <input
                  type="text"
                  value={form.host}
                  onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
                  required
                  className="w-full border border-gray-200 dark:border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
                />
              </div>
              <div className="w-20">
                <label className="text-xs text-gray-500 dark:text-gray-400">Port</label>
                <input
                  type="number"
                  value={form.port}
                  onChange={(e) => setForm((f) => ({ ...f, port: parseInt(e.target.value, 10) || 443 }))}
                  min={1}
                  max={65535}
                  className="w-full border border-gray-200 dark:border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
                />
              </div>
            </div>
          </div>

          {/* Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
              placeholder="My Site"
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
            />
          </div>

          {/* Check interval */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Check Interval (seconds)
            </label>
            <input
              type="number"
              value={form.check_interval_seconds}
              onChange={(e) => setForm((f) => ({ ...f, check_interval_seconds: parseInt(e.target.value, 10) || 3600 }))}
              min={60}
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>

          {/* Expiry threshold */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Alert When Expiring Within
            </label>
            <div className="flex gap-2 flex-wrap">
              {THRESHOLD_PRESETS.map((p) => (
                <button
                  key={p.hours}
                  type="button"
                  onClick={() => {
                    setCustomThreshold(false);
                    setForm((f) => ({ ...f, expiry_threshold_hours: p.hours }));
                  }}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                    isPresetActive(p.hours)
                      ? "bg-blue-600 text-white border-blue-600"
                      : "bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:border-blue-400"
                  }`}
                >
                  {p.label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setCustomThreshold(true)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                  customThreshold
                    ? "bg-blue-600 text-white border-blue-600"
                    : "bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:border-blue-400"
                }`}
              >
                Custom
              </button>
            </div>
            {customThreshold && (
              <div className="mt-2 flex items-center gap-2">
                <input
                  type="number"
                  value={form.expiry_threshold_hours}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, expiry_threshold_hours: parseInt(e.target.value, 10) || 1 }))
                  }
                  min={1}
                  className="w-24 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                />
                <span className="text-sm text-gray-500 dark:text-gray-400">hours</span>
              </div>
            )}
          </div>

          {/* Active */}
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={form.active}
              onChange={(e) => setForm((f) => ({ ...f, active: e.target.checked }))}
              className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">Active</span>
          </label>

          {error && (
            <p className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg px-3 py-2">{error}</p>
          )}

          <div className="flex gap-3 pt-1">
            <button
              type="submit"
              disabled={saving}
              className="flex-1 bg-blue-600 text-white rounded-lg py-2 text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {saving ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg py-2 text-sm font-medium hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
