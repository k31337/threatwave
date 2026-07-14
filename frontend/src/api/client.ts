// Typed client for the ThreatWeave API. Every call goes through `request`, which
// attaches the optional X-API-Key header and turns non-2xx responses into a
// typed `ApiError` carrying the HTTP status, so the UI can render 404/503/429
// distinctly from network failures.

import type { Narrative, SimilarNeighbor, Subgraph } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";
const API_KEY = import.meta.env.VITE_API_KEY ?? "";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function buildUrl(path: string, params: Record<string, string | number | boolean>): string {
  const url = new URL(`${API_BASE}${path}`, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

async function request<T>(
  path: string,
  params: Record<string, string | number | boolean> = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (API_KEY) headers["X-API-Key"] = API_KEY;

  let response: Response;
  try {
    response = await fetch(buildUrl(path, params), { headers });
  } catch (cause) {
    throw new ApiError(0, "Network error: could not reach the API.");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
  return (await response.json()) as T;
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (body && typeof body.detail === "string") return body.detail;
  } catch {
    // Non-JSON error body (e.g. a rate-limit plain-text response); fall through.
  }
  return `Request failed with status ${response.status}.`;
}

export function correlate(
  ioc: string,
  opts: { depth?: number; semantic?: boolean } = {},
): Promise<Subgraph> {
  return request<Subgraph>("/api/correlate", {
    ioc,
    depth: opts.depth ?? 2,
    semantic: opts.semantic ?? false,
  });
}

export function expand(id: string, depth = 1): Promise<Subgraph> {
  return request<Subgraph>("/api/expand", { id, depth });
}

export function similar(id: string, k = 5): Promise<SimilarNeighbor[]> {
  return request<SimilarNeighbor[]>("/api/similar", { id, k });
}

export function narrative(ioc: string, semantic = false): Promise<Narrative> {
  return request<Narrative>("/api/narrative", { ioc, semantic });
}
