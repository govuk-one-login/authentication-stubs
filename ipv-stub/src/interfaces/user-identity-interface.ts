export interface UserIdentity {
  sub: string;
  vot: string;
  vtm: string;
  "https://vocab.account.gov.uk/v1/credentialJWT": string[];
  "https://vocab.account.gov.uk/v1/coreIdentity": CoreIdentity;
  "https://vocab.account.gov.uk/v1/returnCode": ReturnCode[];
}

interface CoreIdentity {
  name: Name[];
  birthDate: BirthDate[];
}

interface Name {
  nameParts: NamePart[];
}

interface NamePart {
  type: string;
  value: string;
}

interface BirthDate {
  value: string;
}

interface ReturnCode {
  code: string;
}
