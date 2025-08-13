import * as jose from "jose";
import { logger } from "./logger.js";
import { CodedError } from "./result-helper.js";

export function processJoseError(error: unknown) {
  if (error instanceof jose.errors.JOSEError) {
    logger.error(error.message);
    throw new CodedError(400, error.code);
  } else {
    logger.error(error);
    throw new CodedError(400, "Unknown error.");
  }
}
