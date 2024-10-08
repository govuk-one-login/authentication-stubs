import { CredentialTrustEnum } from "./credential-trust";

export type Session = {
  session_id: string;
  client_sessions?: string[];
  email_address?: string;
  retry_count?: number;
  password_reset_count?: number;
  code_request_count_map?: { [key: string]: number };
  current_credential_strength?: CredentialTrustEnum;
  is_new_account?: string;
  authenticated?: boolean;
  processing_identity_attempts?: number;
  verified_mfa_method_type?: string;
  internal_common_subject_identifier?: string;
};
