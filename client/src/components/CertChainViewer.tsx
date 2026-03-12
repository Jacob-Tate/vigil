import { useState } from "react";
import { CertChainEntry } from "../types";

interface Props {
  chain: CertChainEntry[];
}

function formatDate(dateStr: string): string {
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

export default function CertChainViewer({ chain }: Props) {
  const [open, setOpen] = useState(false);

  if (chain.length === 0) return null;

  return (
    <div className="mt-4">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 text-sm font-medium text-blue-600 hover:text-blue-800 transition-colors"
      >
        <svg
          className={`w-4 h-4 transition-transform ${open ? "rotate-90" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        {open ? "Hide" : "View"} Certificate Chain ({chain.length})
      </button>

      {open && (
        <div className="mt-3 space-y-0">
          {chain.map((cert, i) => (
            <div key={cert.fingerprint_sha256 || i} className="relative">
              {/* Connector line between cards */}
              {i < chain.length - 1 && (
                <div className="absolute left-6 top-full w-0.5 h-3 bg-gray-300 z-10" />
              )}
              <div className="border border-gray-200 rounded-lg p-3 bg-white text-sm mb-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                    i === 0
                      ? "bg-blue-100 text-blue-700"
                      : cert.is_self_signed
                      ? "bg-gray-100 text-gray-600"
                      : "bg-purple-100 text-purple-700"
                  }`}>
                    {i === 0 ? "Leaf" : cert.is_self_signed ? "Root CA" : `Intermediate ${i}`}
                  </span>
                  {cert.is_self_signed && (
                    <span className="text-xs px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full">
                      Self-signed
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <div>
                    <span className="text-gray-500">Subject</span>
                    <p className="font-medium text-gray-900 truncate">
                      {cert.subject_cn ?? cert.subject_o ?? "—"}
                    </p>
                    {cert.subject_o && cert.subject_cn && (
                      <p className="text-gray-500 truncate">{cert.subject_o}</p>
                    )}
                  </div>
                  <div>
                    <span className="text-gray-500">Issuer</span>
                    <p className="font-medium text-gray-900 truncate">
                      {cert.issuer_cn ?? cert.issuer_o ?? "—"}
                    </p>
                  </div>
                  <div>
                    <span className="text-gray-500">Valid From</span>
                    <p className="text-gray-700">{formatDate(cert.valid_from)}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Valid To</span>
                    <p className="text-gray-700">{formatDate(cert.valid_to)}</p>
                  </div>
                  <div className="col-span-2">
                    <span className="text-gray-500">SHA-256 Fingerprint</span>
                    <p className="font-mono text-gray-600 text-[10px] break-all leading-tight mt-0.5">
                      {cert.fingerprint_sha256}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
