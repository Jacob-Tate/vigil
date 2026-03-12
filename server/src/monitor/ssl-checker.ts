import { connect, DetailedPeerCertificate, TLSSocket } from "node:tls";
import { SslCheckResult, CertChainEntry } from "../types";

const SSL_CONNECT_TIMEOUT_MS = 10_000;

function derToPem(raw: Buffer): string {
  const b64 = raw.toString("base64").match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

function walkChain(leaf: DetailedPeerCertificate): CertChainEntry[] {
  const seen = new Set<string>();
  const entries: CertChainEntry[] = [];
  let current: DetailedPeerCertificate | null = leaf;

  while (current !== null) {
    const fp = current.fingerprint256 ?? "";
    if (seen.has(fp)) break; // circular reference guard — root self-signs

    seen.add(fp);

    const subj = current.subject as Record<string, unknown>;
    const iss = current.issuer as Record<string, unknown>;
    const subjectCn = typeof subj["CN"] === "string" ? subj["CN"] : null;
    const subjectO = typeof subj["O"] === "string" ? subj["O"] : null;
    const issuerCn = typeof iss["CN"] === "string" ? iss["CN"] : null;
    const issuerO = typeof iss["O"] === "string" ? iss["O"] : null;

    const issuerCert: DetailedPeerCertificate | null = current.issuerCertificate ?? null;
    const issuerFp = issuerCert?.fingerprint256 ?? "";
    const isSelfSigned = fp === issuerFp && fp !== "";

    entries.push({
      subject_cn: subjectCn,
      subject_o: subjectO,
      issuer_cn: issuerCn,
      issuer_o: issuerO,
      valid_from: current.valid_from ?? "",
      valid_to: current.valid_to ?? "",
      fingerprint_sha256: fp,
      serial_number: current.serialNumber ?? "",
      is_self_signed: isSelfSigned,
    });

    current = issuerCert ?? null;
  }

  return entries;
}

function buildPemChain(leaf: DetailedPeerCertificate): string {
  const seen = new Set<string>();
  const pems: string[] = [];
  let current: DetailedPeerCertificate | null = leaf;

  while (current !== null) {
    const fp = current.fingerprint256 ?? "";
    if (seen.has(fp)) break;
    seen.add(fp);

    if (current.raw) {
      pems.push(derToPem(current.raw as Buffer));
    }

    current = current.issuerCertificate ?? null;
  }

  return pems.join("\n");
}

const emptyResult: SslCheckResult = {
  error: null,
  tlsVersion: null,
  subjectCn: null,
  subjectO: null,
  issuerCn: null,
  issuerO: null,
  validFrom: null,
  validTo: null,
  daysRemaining: null,
  fingerprintSha256: null,
  serialNumber: null,
  sans: [],
  chain: [],
  pemChain: "",
};

export function checkSslCertificate(host: string, port: number): Promise<SslCheckResult> {
  return new Promise<SslCheckResult>((resolve) => {
    let settled = false;

    function settle(result: SslCheckResult): void {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    }

    const timeoutHandle = setTimeout(() => {
      socket.destroy();
      settle({ ...emptyResult, error: "Connection timeout" });
    }, SSL_CONNECT_TIMEOUT_MS);

    const socket: TLSSocket = connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        clearTimeout(timeoutHandle);

        try {
          // getPeerCertificate(true) returns DetailedPeerCertificate with full chain
          const cert = socket.getPeerCertificate(true) as DetailedPeerCertificate;
          const tlsVersion = socket.getProtocol() ?? null;
          socket.destroy();

          if (!cert || Object.keys(cert).length === 0) {
            settle({ ...emptyResult, error: "No certificate returned", tlsVersion });
            return;
          }

          const chain = walkChain(cert);
          const pemChain = buildPemChain(cert);
          const leaf = chain[0];

          const validTo = cert.valid_to ?? null;
          const daysRemaining =
            validTo !== null
              ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86_400_000)
              : null;

          // subjectaltname is present at runtime but not in @types/node
          const certExtra = cert as unknown as Record<string, string>;
          const rawSans = certExtra["subjectaltname"] ?? "";
          const sans = rawSans
            ? rawSans.split(",").map((s) => s.trim()).filter(Boolean)
            : [];

          settle({
            error: null,
            tlsVersion,
            subjectCn: leaf?.subject_cn ?? null,
            subjectO: leaf?.subject_o ?? null,
            issuerCn: leaf?.issuer_cn ?? null,
            issuerO: leaf?.issuer_o ?? null,
            validFrom: cert.valid_from ?? null,
            validTo,
            daysRemaining,
            fingerprintSha256: cert.fingerprint256 ?? null,
            serialNumber: cert.serialNumber ?? null,
            sans,
            chain,
            pemChain,
          });
        } catch (err) {
          socket.destroy();
          const message = err instanceof Error ? err.message : String(err);
          settle({ ...emptyResult, error: message });
        }
      }
    );

    socket.on("error", (err) => {
      clearTimeout(timeoutHandle);
      settle({ ...emptyResult, error: err.message });
    });
  });
}
