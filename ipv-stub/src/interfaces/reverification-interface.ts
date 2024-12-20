export interface ReverificationSuccess {
  sub: string;
  success: true;
}

export interface ReverificationFailure {
  sub: string;
  success: false;
  failure_code: string;
  failure_description: string;
}

export type Reverification = ReverificationSuccess | ReverificationFailure;
