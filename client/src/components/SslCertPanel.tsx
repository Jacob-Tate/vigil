import { useState } from "react";
import { SslCheck, CertChainEntry } from "../types";
import CertChainViewer from "./CertChainViewer";

interface Props {
  check: SslCheck | null;
  loading: boolean;
  thresholdHours: number;
}

type SslStatus = "valid" | "expiring" | "expired" | "error" | "pending";

function getSslStatus(check: SslCheck | null, thresholdHours: number): SslStatus {
  if (!check) return "pending";
  if (check.error) return "error";
  if (check.days_remaining === null) return "pending";
  if (check.days_remaining < 0) return "expired";
  if (check.days_remaining <= thresholdHours / 24) return "expiring";
  return "valid";
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "—";
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return dateStr;
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={copy}
      className="ml-2 text-xs text-blue-500 hover:text-blue-700 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

const STATUS_STYLES: Record<SslStatus, { pill: string; label: string }> = {
  valid:   { pill: "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400",  label: "Valid" },
  expiring:{ pill: "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400",  label: "Expiring" },
  expired: { pill: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400",          label: "Expired" },
  error:   { pill: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400",          label: "Error" },
  pending: { pill: "bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300",          label: "Pending" },
};

const DAYS_COLOR: (days: number | null) => string = (days) => {
  if (days === null) return "text-gray-500 dark:text-gray-400";
  if (days < 0) return "text-red-600 dark:text-red-400 font-semibold";
  if (days <= 7) return "text-red-600 dark:text-red-400 font-semibold";
  if (days <= 30) return "text-amber-600 dark:text-amber-400 font-semibold";
  return "text-green-600 dark:text-green-400";
};

export default function SslCertPanel({ check, loading, thresholdHours }: Props) {
  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-5">
        <p className="text-sm text-gray-400 dark:text-gray-500">Loading certificate info…</p>
      </div>
    );
  }

  const status = getSslStatus(check, thresholdHours);
  const { pill, label } = STATUS_STYLES[status];

  const chain: CertChainEntry[] = check?.chain_json
    ? (JSON.parse(check.chain_json) as CertChainEntry[])
    : [];

  const sans: string[] = check?.sans
    ? (JSON.parse(check.sans) as string[])
    : [];

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-gray-900 dark:text-white">SSL Certificate</h3>
        <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${pill}`}>{label}</span>
      </div>

      {check?.error ? (
        <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg p-3">
          {check.error}
        </div>
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Days Remaining</dt>
              <dd className={`mt-0.5 text-lg ${DAYS_COLOR(check?.days_remaining ?? null)}`}>
                {check?.days_remaining !== null && check?.days_remaining !== undefined
                  ? `${check.days_remaining} days`
                  : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">TLS Version</dt>
              <dd className="mt-0.5 font-medium text-gray-900 dark:text-white">{check?.tls_version ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Valid From</dt>
              <dd className="mt-0.5 text-gray-700 dark:text-gray-300">{formatDate(check?.valid_from ?? null)}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Valid To</dt>
              <dd className="mt-0.5 text-gray-700 dark:text-gray-300">{formatDate(check?.valid_to ?? null)}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Subject</dt>
              <dd className="mt-0.5 font-medium text-gray-900 dark:text-white truncate">
                {check?.subject_cn ?? "—"}
              </dd>
              {check?.subject_o && (
                <dd className="text-xs text-gray-500 dark:text-gray-400 truncate">{check.subject_o}</dd>
              )}
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Issuer</dt>
              <dd className="mt-0.5 font-medium text-gray-900 dark:text-white truncate">
                {check?.issuer_cn ?? "—"}
              </dd>
              {check?.issuer_o && (
                <dd className="text-xs text-gray-500 dark:text-gray-400 truncate">{check.issuer_o}</dd>
              )}
            </div>
            {check?.serial_number && (
              <div className="col-span-2">
                <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">Serial Number</dt>
                <dd className="mt-0.5 font-mono text-xs text-gray-600 dark:text-gray-400 break-all">
                  {check.serial_number}
                </dd>
              </div>
            )}
            {check?.fingerprint_sha256 && (
              <div className="col-span-2">
                <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide flex items-center">
                  SHA-256 Fingerprint
                  <CopyButton text={check.fingerprint_sha256} />
                </dt>
                <dd className="mt-0.5 font-mono text-xs text-gray-600 dark:text-gray-400 break-all leading-tight">
                  {check.fingerprint_sha256}
                </dd>
              </div>
            )}
            {sans.length > 0 && (
              <div className="col-span-2">
                <dt className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wide">
                  Subject Alternative Names ({sans.length})
                </dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {sans.slice(0, 10).map((san) => (
                    <span
                      key={san}
                      className="text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-1.5 py-0.5 rounded"
                    >
                      {san}
                    </span>
                  ))}
                  {sans.length > 10 && (
                    <span className="text-xs text-gray-400 dark:text-gray-500">+{sans.length - 10} more</span>
                  )}
                </dd>
              </div>
            )}
          </dl>

          <CertChainViewer chain={chain} />
        </>
      )}
    </div>
  );
}
