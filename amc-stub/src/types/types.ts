import { JWTPayload } from "jose";
import { amcScopes } from "./enums.ts";

export interface AccessTokenPayload extends JWTPayload {
  client_id: string;
  scope: amcScopes[];
  sid: string;
}

interface BasePayload extends JWTPayload {
  client_id: string;
  scope: amcScopes[];
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
