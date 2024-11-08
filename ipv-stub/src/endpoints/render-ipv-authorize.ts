import { renderPage } from "../helper/template";
import { DecodedRequest } from "../helper/types";

export default function renderIPVAuthorize(
  decodedHeader: string,
  decodedPayload: DecodedRequest
) {
  return renderPage(
    `<h1 class="govuk-heading-l">IPV stub</h1>
  <h3 class="govuk-heading-s">Decrypted JAR header:</h3>
  <dl class="govuk-summary-list">
  <div class="govuk-summary-list__row">
  <dt class="govuk-summary-list__key">
  Algorithm
  </dt>
  <dd class="govuk-summary-list__value" id="user-info-core-identity-claim-present">
  ${JSON.parse(decodedHeader).alg}
  </dd>
  </dl>

  <dl class="govuk-summary-list">
  <div class="govuk-summary-list__row">
    <dt class="govuk-summary-list__key">
      Decrypted JAR payload
    </dt>
    <dd class="govuk-summary-list__value" id="user-info-core-identity-claim">
    <textarea class="govuk-textarea" rows="10" id="identity_claim" name="identity_claim" type="text">${JSON.stringify(decodedPayload, null, 2)}</textarea>
    </dd>
  </div>
  </dl>`
  );
}
