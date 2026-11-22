/**
 * Two-factor authentication (authenticator app, TOTP) - API /auth/user/mfa, /auth/login/mfa/*
 */
export interface MfaStatus {
  enabled: boolean;
  required: boolean;
  confirmed_at?: string | null;
  recovery_codes_left?: number;
  /** returned once, after setup confirmation or regeneration */
  recovery_codes?: string[];
}

export interface MfaSetup extends MfaStatus {
  secret: string;
  otpauth_uri: string;
  qr_svg?: string | null;
}

/** API error codes of the 2FA flow (errors[].code) */
export enum MfaErrorCode {
  Required = 'mfa_required',
  SetupRequired = 'mfa_setup_required',
  InvalidCode = 'mfa_invalid_code',
  NotAllowed = 'mfa_not_allowed',
}

export function getMfaErrorCode(error: unknown): string | null {
  const errors = (error as { error?: { errors?: { code?: string }[] } } | null)?.error?.errors;
  if (Array.isArray(errors) && errors.length) {
    return errors[0].code || null;
  }
  return null;
}

/** Login response after 2FA setup: recovery codes are returned once in attributes */
export interface MfaLoginResult {
  attributes?: { recovery_codes?: string[] };
}

/** QR code SVG from the API as an <img> source (no inline SVG in the DOM) */
export function mfaQrImageSrc(svg?: string | null): string | null {
  if (!svg) {
    return null;
  }
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}
