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
  `
  );
}
