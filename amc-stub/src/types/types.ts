import { JWTPayload } from "jose";
import { AMCScopes } from "./enums.ts";

export interface AccessTokenPayload extends JWTPayload {
  client_id: string;
  scope: AMCScopes[];
  sid: string;
}

interface BasePayload extends JWTPayload {
  client_id: string;
  scope: AMCScopes[];
  response_type: string;
  redirect_uri: string;
  state: string;
  email: string;
  govuk_signin_journey_id: string;
  public_sub: string;
}

export interface CompositePayload extends BasePayload {
  access_token: AccessTokenPayload;
}

export interface ClientAssertionPayload extends BasePayload {
  access_token: string;
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
