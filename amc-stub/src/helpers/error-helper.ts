import { logger } from "../../logger.ts";
import { CodedError } from "./result-helper.ts";
import { errors } from "jose";

export function processJoseError(error: unknown) {
  if (error instanceof errors.JOSEError) {
    logger.error("jose error: " + error.message);
    throw new CodedError(400, error.code);
  } else {
    logger.error(error);
    throw new CodedError(400, "Unknown error.");
  }
}
