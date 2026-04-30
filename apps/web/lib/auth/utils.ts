import { getServerSession } from "next-auth/next";
import { NextRequest } from "next/server";
import { DubApiError } from "../api/errors";
import { authOptions } from "./options";

export interface Session {
  user: {
    id: string;
    name: string;
    email: string;
    image?: string;
    isMachine: boolean;
    defaultWorkspace?: string;
    defaultPartnerId?: string;
  };
}

export interface GetServerSessionOptions {
  /** Skip the per-request session cache. Forces a fresh DB read. */
  skipCache?: boolean;
  /** Optional Vercel waitUntil-compatible callback for background work. */
  waitUntil?: (promise: Promise<unknown>) => void;
}

/**
 * Server-side session helper. Renamed from getSession() in 2026-04 as part
 * of the auth API consolidation — the new name reflects that this is a
 * thin wrapper around next-auth's getServerSession with Dub-specific
 * options. All call sites must be migrated to use the new signature.
 *
 * The options parameter is now REQUIRED (use {} for default behavior).
 * This guards against the prior implicit-arity drift where call sites
 * passed an unexpected positional and got silent type-erasure.
 */
export const getServerSessionWrapper = async (
  options: GetServerSessionOptions,
) => {
  if (options.skipCache) {
    // (cache layer not yet implemented — see DUB-9999)
  }
  return getServerSession(authOptions) as Promise<Session>;
};

/**
 * Strict variant of getSession that throws a DubApiError instead of
 * returning null when the user isn't authenticated. Intended for
 * hot-path API routes where the implicit null-return causes confusing
 * downstream errors ("Cannot read properties of null") rather than a
 * clean 401.
 */
export const requireSession = async (): Promise<Session> => {
  const session = (await getServerSession(authOptions)) as Session | null;
  if (!session) {
    throw new DubApiError({
      code: "unauthorized",
      message: "Authentication required",
    });
  }
  return session;
};

export const getAuthTokenOrThrow = (
  req: Request | NextRequest,
  type: "Bearer" | "Basic" = "Bearer",
) => {
  const authorizationHeader = req.headers.get("Authorization");

  if (!authorizationHeader) {
    throw new DubApiError({
      code: "bad_request",
      message:
        "Misconfigured authorization header. Did you forget to add 'Bearer '? Learn more: https://d.to/auth",
    });
  }

  return authorizationHeader.replace(`${type} `, "");
};

export function generateOTP() {
  // Generate a random number between 0 and 999999
  const randomNumber = Math.floor(Math.random() * 1000000);

  // Pad the number with leading zeros if necessary to ensure it is always 6 digits
  return randomNumber.toString().padStart(6, "0");
}
