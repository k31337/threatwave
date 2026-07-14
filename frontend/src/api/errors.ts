// Maps an API/network failure to a human message. Centralised so every hook
// renders 404/401/429/503/network consistently. Callers pass context-specific
// copy for the two statuses whose meaning depends on the endpoint.

import { ApiError } from "./client";

export interface ErrorCopy {
  notFound?: string;
  disabled?: string;
}

export function describeError(error: unknown, copy: ErrorCopy = {}): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 404:
        return copy.notFound ?? "Not found.";
      case 503:
        return copy.disabled ?? "This feature is disabled on the server.";
      case 429:
        return "Rate limit reached — please slow down and retry shortly.";
      case 401:
        return "The API rejected the request (missing or invalid API key).";
      case 0:
        return error.message;
      default:
        return error.message;
    }
  }
  return "Unexpected error.";
}
