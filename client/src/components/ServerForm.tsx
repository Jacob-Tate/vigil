import { useState, useEffect, FormEvent } from "react";
import { Server, ServerFormData } from "../types";

interface Props {
  server?: Server | null;
  onSave: (data: ServerFormData) => Promise<void>;
  onClose: () => void;
}

export default function ServerForm({ server, onSave, onClose }: Props) {
  const [form, setForm] = useState<ServerFormData>({
    name: "",
    url: "",
    interval_seconds: 300,
    response_time_threshold_ms: 3000,
    active: true,
    ignore_patterns: [],
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [patternsRaw, setPatternsRaw] = useState("");

  useEffect(() => {
    if (server) {
      let patterns: string[] = [];
      if (server.ignore_patterns) {
        try { patterns = JSON.parse(server.ignore_patterns) as string[]; } catch { /* ignore */ }
      }
      setForm({
        name: server.name,
        url: server.url,
        interval_seconds: server.interval_seconds,
        response_time_threshold_ms: server.response_time_threshold_ms,
        active: server.active === 1,
        ignore_patterns: patterns,
      });
      setPatternsRaw(patterns.join("\n"));
    }
  }, [server]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSave(form);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white">
            {server ? "Edit Server" : "Add Server"}
          </h2>
          <button onClick={onClose} className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300">
            ✕
          </button>
        </div>
        <form onSubmit={(e) => void handleSubmit(e)} className="p-4 flex flex-col gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
            <input
              type="text"
              required
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="My Server"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL</label>
            <input
              type="url"
              required
              value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="https://example.com"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Check interval (s)
              </label>
              <input
                type="number"
                min={30}
                required
                value={form.interval_seconds}
                onChange={(e) =>
                  setForm((f) => ({ ...f, interval_seconds: parseInt(e.target.value, 10) }))
                }
                className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Slow threshold (ms)
              </label>
              <input
                type="number"
                min={100}
                required
                value={form.response_time_threshold_ms}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    response_time_threshold_ms: parseInt(e.target.value, 10),
                  }))
                }
                className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
              />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input
              type="checkbox"
              checked={form.active}
              onChange={(e) => setForm((f) => ({ ...f, active: e.target.checked }))}
              className="rounded"
            />
            Active (monitoring enabled)
          </label>
          <details className="group">
            <summary className="cursor-pointer text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white select-none list-none flex items-center gap-1">
              <span className="transition-transform group-open:rotate-90">▶</span>
              Ignore patterns
            </summary>
            <div className="mt-2">
              <textarea
                rows={4}
                value={patternsRaw}
                onChange={(e) => setPatternsRaw(e.target.value)}
                onBlur={(e) =>
                  setForm((f) => ({
                    ...f,
                    ignore_patterns: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
                  }))
                }
                className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
                placeholder={"sesskey\":\\s*\"[^\"]*\"\nrandom[0-9a-f]{8,}"}
                spellCheck={false}
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                One regex per line. Applied before hashing and diffing to suppress dynamic content.
              </p>
            </div>
          </details>
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm rounded-lg border dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 dark:text-gray-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : server ? "Save changes" : "Add server"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
