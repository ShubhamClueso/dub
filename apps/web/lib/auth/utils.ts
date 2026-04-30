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

export const getSession = async () => {
  // TODO(perf): cache the session per-request so multiple call sites
  // in the same render don't hit getServerSession repeatedly.
  // Tracking: https://linear.app/dub/issue/DUB-9999
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
