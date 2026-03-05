import { renderPage } from "../helpers/template.ts";
import {
  VerifiedAuthorizationRequestPayload,
  ScopeToResultsMap,
} from "../types/types.ts";
import { AMCScopes } from "../types/enums.js";

const scopeToResultsMap: ScopeToResultsMap = {
  [AMCScopes.PASSKEY_CREATE]: getPasskeyCreateResults(),
  [AMCScopes.ACCOUNT_DELETE]: getAccountDeleteResults(),
};

export default function renderAmcAuthorize(
  decodedHeader: string,
  decodedPayload: VerifiedAuthorizationRequestPayload,
  scope: AMCScopes
) {
  return renderPage(
    `<style>.json-formatter{font-family:monospace;white-space:pre-wrap;background:#f8f8f8;padding:10px;border:1px solid #ddd}</style>
  <h1 class="govuk-heading-l">AMC stub ${scope ? sanitiseScope(scope) : ""}</h1>
  <h3 class="govuk-heading-s">Decrypted JAR header</h3>
  <dl class="govuk-summary-list">
  <div class="govuk-summary-list__row">
  <dt class="govuk-summary-list__key">
  Algorithm:
  </dt>
  <dd class="govuk-summary-list__value" id="user-info-core-identity-claim-present">
  ${decodedHeader}
  </dd>
  </dl>

  <dl class="govuk-summary-list">
  <div class="govuk-summary-list__row">
    <dt class="govuk-summary-list__key">
      Decrypted JAR payload:
    </dt>
  </div>
  <div class="govuk-summary-list__row">
    <dd class="govuk-summary-list__value" id="user-info-core-identity-claim">
        <div class="json-formatter">${JSON.stringify(decodedPayload, null, 2)}</div>
    </dd>
  </div>
  </dl>

  <form action="/authorize" method="post">
  <div class="govuk-form-group">
  <fieldset class="govuk-fieldset">
    <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
        <h2 class="govuk-fieldset__heading">
            AMC Response ${sanitiseScope(scope)}
        </h2>
    </legend>
    <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
    ${scopeToResultsMap[scope]}
    </div>
  </fieldset>
  </div>
  <button name="continue" value="continue" class="govuk-button">Continue</button>
  <input type="hidden" name="state" value=${decodedPayload.state}>
  <input type="hidden" name="sub" value=${decodedPayload.sub}>
  <input type="hidden" name="redirect_uri" value=${decodedPayload.redirect_uri}>
  <input type="hidden" name="email" value=${decodedPayload.email}>
  <input type="hidden" name="scope" value=${decodedPayload.scope}>
  </form>
  `
  );
}

function getPasskeyCreateResults() {
  return `
  <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="success" name="response" type="radio" value="success" checked>
            <label class="govuk-label govuk-radios__label" for="success">
                Success
            </label>
        </div>

  <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="fail" name="response" type="radio" value="fail">
            <label class="govuk-label govuk-radios__label" for="fail">
                Fail
            </label>
        </div>

  <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="back" name="response" type="radio" value="back">
            <label class="govuk-label govuk-radios__label" for="back">
                Back
            </label>
        </div>

  <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="skip" name="response" type="radio" value="skip">
            <label class="govuk-label govuk-radios__label" for="skip">
                Skip
            </label>
        </div>
  `;
}

function getAccountDeleteResults() {
  return `
  <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="success" name="response" type="radio" value="success" checked>
            <label class="govuk-label govuk-radios__label" for="success">
                Success
            </label>
        </div>
  `;
}

const sanitiseScope = (scope: string) => `(${scope.split("-").join(" ")})`;
