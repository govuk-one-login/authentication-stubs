import { JWTPayload } from "jose";
import { AccessTokenApi, AMCScopes } from "./enums.js";

export interface AccessTokenPayload extends JWTPayload {
  client_id: string;
  scope: string;
  sid: string;
}

interface BasePayload extends JWTPayload {
  client_id: string;
  scope: string;
  response_type: string;
  redirect_uri: string;
  state: string;
  email: string;
  public_sub: string;
}

export interface VerifiedAuthorizationRequestPayload extends BasePayload {
  account_management_api_access_token?: AccessTokenPayload;
  account_data_api_access_token?: AccessTokenPayload;
}

export interface AuthorizationRequestPayload extends BasePayload {
  account_management_api_access_token?: string;
  account_data_api_access_token?: string;
}

export interface AMCAuthorizationResult {
  sub: string;
  outcome_id: string;
  email: string;
  scope: string;
  success: boolean;
  actions: AMCAction[];
}

export interface AMCAction {
  action: string;
  startedAt: number;
  completedAt: number;
  success: boolean;
  details: AMCActionErrorDetails | object;
}

export interface AMCActionErrorDetails {
  error: {
    code: number;
    description: string;
  };
  accountInterventionsStatus?: {
    state: {
      blocked: boolean;
      reproveIdentity: boolean;
      resetPassword: boolean;
      suspended: boolean;
    };
  };
}

type AMCScopesValues = (typeof AMCScopes)[keyof typeof AMCScopes];

export type ScopeToResultsMap = {
  [a in AMCScopesValues]: string;
};

type PasskeysCreateResponse = "success" | "back" | "skip";
type AccountDeleteResponse = "success";

export type AMCAuthorizeResponse =
  | PasskeysCreateResponse
  | AccountDeleteResponse;

export type AccountInterventionType =
  | "none"
  | "blocked"
  | "reprove-identity"
  | "reset-password"
  | "suspended";

export interface ParsedBody {
  sub: string;
  response: AMCAuthorizeResponse;
  state: string;
  redirect_uri: string;
  email: string;
  scope: AMCScopesValues;
  "account-interventions"?: AccountInterventionType[];
}

export interface JwksConfig {
  jwksEndpoint: string;
  backupKey: string;
}

export type AccessTokenApiType =
  (typeof AccessTokenApi)[keyof typeof AccessTokenApi];
