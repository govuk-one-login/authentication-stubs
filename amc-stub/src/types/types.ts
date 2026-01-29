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

export interface AMCSuccess {
  sub: string;
  success: true;
}

export interface AMCFailure {
  sub: string;
  success: false;
  failure_code: string;
  failure_description: string;
}

export type AMCAuthorizationResult = AMCSuccess | AMCFailure;
