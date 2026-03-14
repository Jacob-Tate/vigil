import { useState, useEffect, FormEvent } from "react";
import { NotifierTypeDef, NotificationChannel } from "../types";

interface Props {
  types: NotifierTypeDef[];
  channel?: NotificationChannel | null;
  onSave: (data: { type: string; label?: string; config: Record<string, unknown>; active?: boolean }) => Promise<void>;
  onClose: () => void;
}

export default function NotifierForm({ types, channel, onSave, onClose }: Props) {
  const [selectedType, setSelectedType] = useState<string>(channel?.type ?? types[0]?.type ?? "");
  const [label, setLabel] = useState(channel?.label ?? "");
  const [active, setActive] = useState(channel ? channel.active === 1 : true);
  const [config, setConfig] = useState<Record<string, string>>(
    channel ? Object.fromEntries(Object.entries(channel.config).map(([k, v]) => [k, String(v)])) : {}
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = ""; };
  }, []);

  // If types loaded after the form mounted (race condition), sync the selection
  useEffect(() => {
    if (!channel && selectedType === "" && types.length > 0) {
      setSelectedType(types[0].type);
    }
  }, [types, channel, selectedType]);

  const typeDef = types.find((t) => t.type === selectedType);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSave({ type: selectedType, label: label || undefined, config, active });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white">
            {channel ? "Edit Notification Channel" : "Add Notification Channel"}
          </h2>
          <button onClick={onClose} className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300">✕</button>
        </div>
        <form onSubmit={(e) => void handleSubmit(e)} className="p-4 flex flex-col gap-4">
          {!channel && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
              <select
                value={selectedType}
                onChange={(e) => {
                  setSelectedType(e.target.value);
                  setConfig({});
                }}
                className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
              >
                {types.map((t) => (
                  <option key={t.type} value={t.type}>{t.displayName}</option>
                ))}
              </select>
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Label <span className="text-gray-400 dark:text-gray-500 font-normal">(optional)</span>
            </label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="e.g. #alerts channel"
            />
          </div>
          {typeDef &&
            Object.entries(typeDef.configSchema).map(([key, field]) => (
              <div key={key}>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  {field.label}
                  {field.required && <span className="text-red-500 ml-1">*</span>}
                </label>
                <input
                  type={field.type}
                  required={field.required}
                  value={config[key] ?? ""}
                  onChange={(e) => setConfig((c) => ({ ...c, [key]: e.target.value }))}
                  placeholder={field.placeholder}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
                />
              </div>
            ))}
          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
              className="rounded"
            />
            Active
          </label>
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-lg border dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 dark:text-gray-300">
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : channel ? "Save changes" : "Add channel"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
