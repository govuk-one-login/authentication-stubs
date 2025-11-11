import { renderPage } from "../helper/template";
import { DecodedRequest } from "../helper/types";

export default function renderIPVAuthorize(
  decodedHeader: string,
  decodedPayload: DecodedRequest
) {
  return renderPage(
    `<style>.json-formatter{font-family:monospace;white-space:pre-wrap;background:#f8f8f8;padding:10px;border:1px solid #ddd}</style>
  <h1 class="govuk-heading-l">IPV stub</h1>
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
  <div class="govuk-summary-list__row">
    <dd class="govuk-summary-list__value">
        Note.  The values part of the storageAccessToken is not rendered correctly, there is no "0" key it is a list of strings.
    </dd>
  </div>
  </dl>

  <form action="/authorize" method="post">
    <div class="govuk-form-group">
    <fieldset class="govuk-fieldset">
      <legend class="govuk-fieldset__legend govuk-fieldset__legend--l">
          <h2 class="govuk-fieldset__heading">
              IPV Response 
          </h2>
      </legend>
      <div class="govuk-radios govuk-radios--inline" data-module="govuk-radios">
          <div class="govuk-radios__item">
              <input class="govuk-radios__input" id="success" name="response" type="radio" value="success" checked>
              <label class="govuk-label govuk-radios__label" for="success">
                  Success
              </label>
          </div>
          <div class="govuk-radios__item">
              <input class="govuk-radios__input" id="no_identity_available" name="response" type="radio" value="no_identity_available">
              <label class="govuk-label govuk-radios__label" for="no_identity_available">
                  No identity available
              </label>
          </div>
          <div class="govuk-radios__item">
              <input class="govuk-radios__input" id="identity_check_incomplete" name="response" type="radio" value="identity_check_incomplete">
              <label class="govuk-label govuk-radios__label" for="identity_check_incomplete">
                  Identity check incomplete
              </label>
          </div>
          <div class="govuk-radios__item">
              <input class="govuk-radios__input" id="identity_check_failed" name="response" type="radio" value="identity_check_failed">
              <label class="govuk-label govuk-radios__label" for="identity_check_failed">
                  Identity check failed
              </label>
          </div>
          <div class="govuk-radios__item">
              <input class="govuk-radios__input" id="identity_did_not_match" name="response" type="radio" value="identity_did_not_match">
              <label class="govuk-label govuk-radios__label" for="identity_did_not_match">
                  Identity did not match
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
  <div class="govuk-inset-text">
    To test the cross browser issue, open the following in a new private window: <a href="${decodedPayload.redirect_uri}?state=${decodedPayload.state}&error=access_denied">${decodedPayload.redirect_uri}?state=${decodedPayload.state}&error=access_denied</a>
  </div>
  `
  );
}
