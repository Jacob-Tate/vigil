import { Router, Request, Response } from "express";
import { query, param, validationResult } from "express-validator";
import { dbAll, dbGet } from "../db/database";
import { NvdCveDetail, NvdCveRef, NvdCpeEntry } from "../types";

const router = Router();

interface NvdCveRow {
  cve_id: string;
  published_at: string | null;
  last_modified_at: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string | null;
  nvd_url: string | null;
  references_json: string | null;
  is_kev: number | null;
}

interface KevRow {
  date_added: string | null;
  vulnerability_name: string | null;
  required_action: string | null;
  due_date: string | null;
  known_ransomware_campaign_use: string | null;
}

// GET /api/nvd/browse/search?q=&severity=&minScore=&from=&to=&kev=&page=&limit=
router.get(
  "/search",
  query("q").optional().isString(),
  query("severity")
    .optional()
    .isIn(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", ""]),
  query("minScore").optional().isFloat({ min: 0, max: 10 }),
  query("from").optional().isISO8601(),
  query("to").optional().isISO8601(),
  query("kev").optional().isIn(["true", "false", ""]),
  query("page").optional().isInt({ min: 1 }),
  query("limit").optional().isInt({ min: 1, max: 200 }),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const q = (req.query["q"] as string | undefined)?.trim() ?? "";
    const severity = (req.query["severity"] as string | undefined) ?? "";
    const minScore =
      req.query["minScore"] !== undefined
        ? parseFloat(req.query["minScore"] as string)
        : null;
    const from = (req.query["from"] as string | undefined) ?? "";
    const to = (req.query["to"] as string | undefined) ?? "";
    const kevOnly = req.query["kev"] === "true";
    const page = parseInt((req.query["page"] as string | undefined) ?? "1", 10);
    const limit = parseInt(
      (req.query["limit"] as string | undefined) ?? "50",
      10
    );
    const offset = (page - 1) * limit;

    // Build dynamic WHERE clauses using [sqlFragment, ...bindParams] tuples.
    // The SQL fragment must always be a string literal — user input belongs
    // only in the bind params positions, never in the fragment itself.
    type Condition = [string, ...unknown[]];
    const clauses: Condition[] = [];

    if (q) clauses.push(["(c.cve_id LIKE ? OR c.description LIKE ?)", `%${q}%`, `%${q}%`]);
    if (severity) clauses.push(["c.cvss_severity = ?", severity]);
    if (minScore !== null) clauses.push(["c.cvss_score >= ?", minScore]);
    if (from) clauses.push(["c.published_at >= ?", from]);
    if (to) clauses.push(["c.published_at <= ?", `${to}T23:59:59`]);
    if (kevOnly) clauses.push(["k.cve_id IS NOT NULL"]);

    const where = clauses.length > 0
      ? `WHERE ${clauses.map(([fragment]) => fragment).join(" AND ")}`
      : "";
    const params = clauses.flatMap(([, ...p]) => p);

    const total =
      dbGet<{ cnt: number }>(
        `SELECT COUNT(*) AS cnt
         FROM nvd_cves c
         LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
         ${where}`,
        ...params
      )?.cnt ?? 0;

    const data = dbAll<NvdCveRow>(
      `SELECT c.cve_id, c.published_at, c.last_modified_at, c.cvss_score,
              c.cvss_severity, c.description, c.nvd_url,
              CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_kev
       FROM nvd_cves c
       LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
       ${where}
       ORDER BY c.published_at DESC
       LIMIT ? OFFSET ?`,
      ...params,
      limit,
      offset
    );

    res.json({
      data,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  }
);

// GET /api/nvd/browse/cve/:cveId
router.get(
  "/cve/:cveId",
  param("cveId").isString().trim().notEmpty(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const cveId = req.params["cveId"] as string;

    const row = dbGet<NvdCveRow>(
      "SELECT * FROM nvd_cves WHERE cve_id = ?",
      cveId
    );
    if (!row) {
      res.status(404).json({ error: "CVE not found" });
      return;
    }

    const cpeRows = dbAll<NvdCpeEntry>(
      `SELECT cpe_string, version_start_including, version_start_excluding,
              version_end_including, version_end_excluding
       FROM nvd_cve_cpes WHERE cve_id = ?
       ORDER BY cpe_string, version_start_including, version_start_excluding`,
      cveId
    );

    let references: NvdCveRef[] = [];
    if (row.references_json) {
      try {
        references = JSON.parse(row.references_json) as NvdCveRef[];
      } catch { /* malformed JSON — leave empty */ }
    }

    const kevRow = dbGet<KevRow>(
      `SELECT date_added, vulnerability_name, required_action, due_date,
              known_ransomware_campaign_use
       FROM cisa_kev WHERE cve_id = ?`,
      cveId
    );

    const detail: NvdCveDetail = {
      cve_id: row.cve_id,
      published_at: row.published_at,
      last_modified_at: row.last_modified_at,
      cvss_score: row.cvss_score,
      cvss_severity: row.cvss_severity,
      description: row.description,
      nvd_url: row.nvd_url,
      cpe_entries: cpeRows,
      references,
      kev: kevRow?.date_added
        ? {
            date_added: kevRow.date_added,
            vulnerability_name: kevRow.vulnerability_name,
            required_action: kevRow.required_action,
            due_date: kevRow.due_date,
            known_ransomware_campaign_use: kevRow.known_ransomware_campaign_use,
          }
        : null,
    };

    res.json(detail);
  }
);

export { router as nvdBrowseRouter };
