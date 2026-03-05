import { JWTPayload } from "jose";
import { AMCScopes } from "./enums.js";

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
  access_token: AccessTokenPayload;
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
  journeys: AMCJourney[];
}

export interface AMCJourney {
  journey: string;
  timestamp: number;
  success: boolean;
  details: AMCJourneyErrorDetails | object;
}

export interface AMCJourneyErrorDetails {
  error: {
    code: number;
    description: string;
  };
}

type AMCScopesValues = (typeof AMCScopes)[keyof typeof AMCScopes];

export type ScopeToResultsMap = {
  [a in AMCScopesValues]: string;
};

type PasskeysCreateResponse = "fail" | "success" | "back" | "skip";
type AccountDeleteResponse = "success";

export type AMCAuthorizeResponse =
  | PasskeysCreateResponse
  | AccountDeleteResponse;

export interface ParsedBody {
  sub: string;
  response: AMCAuthorizeResponse;
  state: string;
  redirect_uri: string;
  email: string;
  scope: AMCScopesValues;
}
