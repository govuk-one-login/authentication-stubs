import { JWTPayload } from "jose";
import { amcScopes } from "./enums.ts";

export interface AccessTokenPayload extends JWTPayload {
  client_id: string;
  scope: amcScopes[];
  sid: string;
}

export interface CompositePayload extends JWTPayload {
  client_id: string;
  scope: amcScopes[];
  response_type: string;
  redirect_uri: string;
  state: string;
  access_token: AccessTokenPayload;
  email: string;
  govuk_signin_journey_id: string;
  public_sub: string;
}
