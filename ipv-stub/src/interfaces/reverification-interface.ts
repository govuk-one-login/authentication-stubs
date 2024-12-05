export interface Reverification {
  sub: string;
  success: boolean;
  failure_code?: string;
  failure_description?: string;
}
