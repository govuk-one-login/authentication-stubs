import { renderPage } from "../helpers/template.ts";
import { CompositePayload } from "../types/types.ts";

export default function renderAmcAuthorize(
  decodedHeader: string,
  decodedPayload: CompositePayload
) {
  return renderPage(
    `<style>.json-formatter{font-family:monospace;white-space:pre-wrap;background:#f8f8f8;padding:10px;border:1px solid #ddd}</style>
  <h1 class="govuk-heading-l">AMC stub</h1>
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
            AMC Response 
        </h2>
    </legend>
    <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
        <div class="govuk-radios__item">
            <input class="govuk-radios__input" id="success" name="response" type="radio" value="success" checked>
            <label class="govuk-label govuk-radios__label" for="success">
                Success
            </label>
        </div>
    </div>
  </fieldset>
  </div>
  <button name="continue" value="continue" class="govuk-button">Continue</button>
  <input type="hidden" name="state" value=${decodedPayload.state}>
  <input type="hidden" name="sub" value=${decodedPayload.sub}>
  <input type="hidden" name="redirect_uri" value=${decodedPayload.redirect_uri}>
  </form>
  `
  );
}
