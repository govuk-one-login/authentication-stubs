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

  ${scope === AMCScopes.PASSKEY_CREATE ? getAccountInterventionTypeCheckboxes() : ""}

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
            <input class="govuk-radios__input" id="account-interventions-failure" name="response" type="radio" value="account-interventions-failure">
            <label class="govuk-label govuk-radios__label" for="account-interventions-failure">
                Account Interventions Failure
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

function getAccountInterventionTypeCheckboxes() {
  return `
  <div class="govuk-form-group" id="account-interventions-group" style="display:none;">
  <fieldset class="govuk-fieldset">
    <legend class="govuk-fieldset__legend govuk-fieldset__legend--m">
        <h3 class="govuk-fieldset__heading">
            Account interventions type
        </h3>
    </legend>
    <div class="govuk-hint">Optional. Select one or more. Only applies when response is not success.</div>
    <div class="govuk-checkboxes" data-module="govuk-checkboxes">
        <div class="govuk-checkboxes__item">
            <input class="govuk-checkboxes__input" id="account-interventions-blocked" name="account-interventions" type="checkbox" value="blocked">
            <label class="govuk-label govuk-checkboxes__label" for="account-interventions-blocked">
                Blocked
            </label>
        </div>
        <div class="govuk-checkboxes__item">
            <input class="govuk-checkboxes__input" id="account-interventions-reprove-identity" name="account-interventions" type="checkbox" value="reprove-identity">
            <label class="govuk-label govuk-checkboxes__label" for="account-interventions-reprove-identity">
                Reprove identity
            </label>
        </div>
        <div class="govuk-checkboxes__item">
            <input class="govuk-checkboxes__input" id="account-interventions-reset-password" name="account-interventions" type="checkbox" value="reset-password">
            <label class="govuk-label govuk-checkboxes__label" for="account-interventions-reset-password">
                Reset password
            </label>
        </div>
        <div class="govuk-checkboxes__item">
            <input class="govuk-checkboxes__input" id="account-interventions-suspended" name="account-interventions" type="checkbox" value="suspended">
            <label class="govuk-label govuk-checkboxes__label" for="account-interventions-suspended">
                Suspended
            </label>
        </div>
    </div>
  </fieldset>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      var responseRadios = document.querySelectorAll('input[name="response"]');
      var accountInterventionsGroup = document.getElementById('account-interventions-group');
      function toggleAccountInterventionsGroup() {
        var selected = document.querySelector('input[name="response"]:checked');
        accountInterventionsGroup.style.display = (selected && selected.value === 'account-interventions-failure') ? '' : 'none';
      }
      responseRadios.forEach(function(radio) {
        radio.addEventListener('change', toggleAccountInterventionsGroup);
      });
      toggleAccountInterventionsGroup();
    });
  </script>
  `;
}

const sanitiseScope = (scope: string) => `(${scope.split("-").join(" ")})`;
