import {
  APIGatewayProxyEvent,
  APIGatewayProxyEventHeaders,
  APIGatewayProxyResult,
} from "aws-lambda";
import * as jose from "jose";
import { JWTPayload } from "jose";
import { getCookie, getOrCreatePersistentSessionId } from "../utils/cookie";
import crypto from "node:crypto";
import { downcaseHeaders } from "../utils/headers";
import { Session } from "../types/session";
import { getRedisClient, getSession } from "../services/redis";
import { ClientSession } from "../types/client-session";
import * as process from "node:process";
import { getPrivateKey } from "../utils/key";
import { renderGovukPage } from "../utils/page";
import {
  parseRequestParameters,
  RequestParameters,
} from "../services/request-parameters";
import { credentialTrustToEnum } from "../types/credential-trust";
import { AccountStateEnum } from "../types/account-state";

const RP_STATE = "dwG_gAlpIuRK-6FKReKEnoNUZdwgy8BUxYKUaXmIXeY";
const RP_REDIRECT_URI = "https://a.example.com/redirect";
export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  downcaseHeaders(event);
  const method = event.httpMethod.toUpperCase();
  switch (method) {
    case "GET":
      return get(event);
    case "POST":
      return post(event);
    default:
      return {
        statusCode: 405,
        body: JSON.stringify({
          message: "Method not allowed: " + method,
        }),
      };
  }
};

const get = (_event: APIGatewayProxyEvent): APIGatewayProxyResult => {
  const form = `<h1 class="govuk-heading-xl">Orchestration stub</h1>
<form method='post'>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                Reauthentication
            </h2>
        </legend>
        <label for="reauthenticate" class="govuk-label">RP pairwise ID</label>
        <input name="reauthenticate" id="reauthenticate" class="govuk-input">
    </fieldset>
    </div>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                MFA
            </h2>
        </legend>
        <label for="level" class="govuk-label">Credential Trust Level</label>
        <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="level" name="level" type="radio" value="Cl.Cm" checked>
                <label class="govuk-label govuk-radios__label" for="level">
                    Cl.Cm (2FA)
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="level-2" name="level" type="radio" value="Cl">
                <label class="govuk-label govuk-radios__label" for="level-2">
                    Cl (No 2FA)
                </label>
            </div>
        </div>
    </fieldset>
    </div>
    <div class="govuk-form-group">
        <fieldset class="govuk-fieldset">
            <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
                <h2 class="govuk-fieldset__heading">
                    Seamless login and uplift
                </h2>
            </legend>
            <div class="govuk-radios" data-module="govuk-radios">
                <div class="govuk-radios__item">
                    <input class="govuk-radios__input" id="authenticated" name="authenticated" type="radio" value="no"
                           checked>
                    <label class="govuk-label govuk-radios__label" for="authenticated">
                        Not authenticated
                    </label>
                </div>
                <div class="govuk-radios__item">
                    <input class="govuk-radios__input" id="authenticated-2" name="authenticated" type="radio"
                           value="yes" data-aria-controls="conditional-authenticated-2">
                    <label class="govuk-label govuk-radios__label" for="authenticated-2">
                        Authenticated
                    </label>
                    <div class="govuk-hint govuk-radios__hint">
                        You need to sign in at least once before selecting this option so that the email and internal
                        common subject identifier are set on the session
                    </div>
                </div>
        </fieldset>
    </div>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                Channel
            </h2>
        </legend>
        <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="channel-none" name="channel" type="radio" value="none" checked>
                <label class="govuk-label govuk-radios__label" for="channel-none">
                    None
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="channel-web" name="channel" type="radio" value="web">
                <label class="govuk-label govuk-radios__label" for="channel-web">
                    Web
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="channel-strategic-app" name="channel" type="radio" value="strategic_app">
                <label class="govuk-label govuk-radios__label" for="channel-strategic-app">
                    Strategic App
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="channel-generic-app" name="channel" type="radio" value="generic_app">
                <label class="govuk-label govuk-radios__label" for="channel-generic-app">
                    Generic App
                </label>
            </div>
        </div>
    </fieldset>
    </div>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h4 class="govuk-fieldset__heading">
                Cookie Consent
            </h4>
        </legend>
        <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="cookie-consent-none" name="cookie-consent" type="radio" value="none" checked>
                <label class="govuk-label govuk-radios__label" for="cookie-consent-none">
                    none
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="cookie-consent-accept" name="cookie-consent" type="radio" value="accept">
                <label class="govuk-label govuk-radios__label" for="cookie-consent-accept">
                    accept
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="cookie-consent-reject" name="cookie-consent" type="radio" value="reject">
                <label class="govuk-label govuk-radios__label" for="cookie-consent-reject">
                    reject
                </label>
            </div>
            <div class="govuk-radios__item">
                <input class="govuk-radios__input" id="cookie-consent-not-engaged" name="cookie-consent" type="radio" value="not-engaged">
                <label class="govuk-label govuk-radios__label" for="cookie-consent-not-engaged">
                    not engaged
                </label>
            </div>
        </div>
    </fieldset>
    </div>
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
        <legend id="login-hint-legend" class="govuk-fieldset__legend govuk-fieldset__legend--l">
            <h2 class="govuk-fieldset__heading">
                Login hint
            </h2>
        </legend>
        <input name="login-hint" id="login-hint" class="govuk-input" maxlength="256" aria-labelledby="login-hint-legend">
    </fieldset>
    </div>
    <button class="govuk-button">Submit</button>
</form>
`;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: renderGovukPage(form),
  };
};

const post = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const form = parseRequestParameters(event.body);
  const previousSessionId = getCookie(event.headers["cookie"], "gs")?.split(
    ".",
  )[0];
  const gsCookie = await setUpSession(event.headers, form);

  //Isn't the journeyId the at index [1]?
  const journeyId = gsCookie.split(".")[0];
  const signingPrivKey = await getPrivateKey();
  const payload = jarPayload(form, journeyId, previousSessionId);
  const jws = await signRequestObject(payload, signingPrivKey);
  const jwe = await encryptRequestObject(jws, await sandpitFrontendPublicKey());

  const persistentSessionId = getOrCreatePersistentSessionId(event.headers);
  const cookieDomain =
    process.env.COOKIE_DOMAIN === "none"
      ? ""
      : `; Domain=${process.env.COOKIE_DOMAIN}`;
  return {
    statusCode: 302,
    multiValueHeaders: {
      Location: [
        `${process.env.AUTHENTICATION_FRONTEND_URL}authorize?request=${jwe}&response_type=code&client_id=orchestrationAuth`,
      ],
      "Set-Cookie": [
        `gs=${gsCookie}; max-age=3600${cookieDomain}`,
        `di-persistent-session-id=${persistentSessionId}; max-age=34190000${cookieDomain}`,
      ],
    },
    body: "",
  };
};

const jarPayload = (
  form: RequestParameters,
  journeyId: string,
  previousSessionId: string | undefined,
): JWTPayload => {
  const claim = {
    userinfo: {
      salt: "",
      email: "",
      email_verified: "",
      phone_number: "",
      phone_number_verified: "",
      local_account_id: "",
      public_account_id: "",
      legacy_account_id: "",
    },
  };
  const payload: JWTPayload = {
    rp_client_id: process.env.RP_CLIENT_ID,
    rp_sector_host: process.env.RP_SECTOR_HOST,
    rp_redirect_uri: "https://a.example.com/redirect",
    rp_state: RP_STATE,
    client_name: "client",
    cookie_consent_shared: true,
    is_one_login_service: false,
    service_type: "essential",
    govuk_signin_journey_id: journeyId,
    state: "3",
    client_id: "orchestrationAuth",
    redirect_uri: `https://${process.env.STUB_DOMAIN}/orchestration-redirect`,
    claim: JSON.stringify(claim),
    authenticated: form.authenticated ?? false,
    scope: "openid email phone",
    requested_credential_strength: form.confidence,
    is_smoke_test: false,
    subject_type: "pairwise",
    is_identity_verification_required: false,
  };
  if (form["reauthenticate"] !== "") {
    payload["reauthenticate"] = form["reauthenticate"];
  }
  if (form.channel !== "none") {
    payload["channel"] = form.channel;
  }

  if (previousSessionId) {
    payload["previous_session_id"] = previousSessionId;
  }
  if (form.cookieConsent !== "none") {
    payload["cookie_consent"] = form.cookieConsent;
  }
  if (form.loginHint !== "") {
    payload["login_hint"] = form.loginHint;
  }
  return payload;
};

const sandpitFrontendPublicKey = async () =>
  await jose.importSPKI(process.env.AUTH_PUB_KEY!, "RS256");

const signRequestObject = async (
  payload: JWTPayload,
  signingPrivKey: jose.KeyLike,
) => {
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchestrationAuth")
    .setAudience(process.env.AUTHENTICATION_FRONTEND_URL!)
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("2h")
    .setJti("4")
    .sign(signingPrivKey);
};

const encryptRequestObject = async (jws: string, encPubKey: jose.KeyLike) =>
  await new jose.CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({ cty: "JWT", alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(encPubKey);

const setUpSession = async (
  headers: APIGatewayProxyEventHeaders,
  config: RequestParameters,
) => {
  const newSessionId = crypto.randomBytes(20).toString("base64url");
  const newClientSessionId = crypto.randomBytes(20).toString("base64url");
  await createNewClientSession(newClientSessionId, config);

  const existingGsCookie = getCookie(headers["cookie"], "gs");
  if (existingGsCookie) {
    const idParts = existingGsCookie.split(".");
    const sessionId = idParts[0];
    try {
      await renameExistingSession(sessionId, newSessionId, config);
    } catch (_e) {
      await createNewSession(newSessionId, config);
    }
  } else {
    await createNewSession(newSessionId, config);
  }
  await attachClientSessionToSession(newClientSessionId, newSessionId);

  return `${newSessionId}.${newClientSessionId}`;
};

const createNewClientSession = async (
  id: string,
  config: RequestParameters,
) => {
  const client = await getRedisClient();
  var auth_request_params: { [key: string]: string[] } = {
    vtr: [`[${config.confidence}]`],
    scope: ["openid email phone"],
    response_type: ["code"],
    redirect_uri: [RP_REDIRECT_URI],
    state: [RP_STATE],
    prompt: ["none"],
    nonce: ["AJYiGSXv6euaffiuG5jMNgCwQW0ne7yuqDR9PrjsuvQ"],
    client_id: [process.env.RP_CLIENT_ID!],
  };
  if (config.cookieConsent) {
    auth_request_params["cookie_consent"] = [config.cookieConsent];
  }
  const clientSession: ClientSession = {
    creation_time: new Date(),
    client_name: "Example RP",
    auth_request_params,
    effective_vector_of_trust: {
      credential_trust_level: credentialTrustToEnum(config.confidence),
    },
  };
  await client.setEx(
    `client-session-${id}`,
    3600,
    JSON.stringify(clientSession),
  );
};

const createNewSession = async (id: string, config: RequestParameters) => {
  const session: Session = {
    session_id: id,
    code_request_count_map: {},
    authenticated: config.authenticated,
    is_new_account: AccountStateEnum.UNKNOWN,
  };
  const client = await getRedisClient();
  await client.setEx(id, 3600, JSON.stringify(session));
};

const renameExistingSession = async (
  existingSessionId: string,
  newSessionId: string,
  config: RequestParameters,
) => {
  const client = await getRedisClient();
  const existingSession = await getSession(existingSessionId);
  await client.del(existingSessionId);
  existingSession.session_id = newSessionId;
  existingSession.authenticated = config.authenticated;
  await client.setEx(newSessionId, 3600, JSON.stringify(existingSession));
};

const attachClientSessionToSession = async (
  clientSessionId: string,
  sessionId: string,
) => {
  const client = await getRedisClient();
  const session = await getSession(sessionId);

  session.client_sessions ||= [];
  session.client_sessions.push(clientSessionId);

  await client.setEx(sessionId, 3600, JSON.stringify(session));
};
