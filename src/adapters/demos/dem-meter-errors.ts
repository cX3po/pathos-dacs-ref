export type MeterErrorCode =
  | 'meter-busy'
  | 'partial-tail'
  | 'head-missing'
  | 'head-mismatch'
  | 'meter-invalid'
  | 'meter-io'
  | 'meter-failed';

export interface MeterErrorResult {
  code: MeterErrorCode;
  message: string;
}

export class DemMeterError extends Error {
  constructor(public readonly code: MeterErrorCode, message: string) {
    super(message);
    this.name = 'DemMeterError';
  }
}

const METER_ERROR_MESSAGES: Record<MeterErrorCode, string> = {
  'meter-busy': 'DEM meter is busy',
  'partial-tail': 'DEM meter has a partial trailing row',
  'head-missing': 'DEM meter truncation guard is missing',
  'head-mismatch': 'DEM meter truncation guard does not match the log',
  'meter-invalid': 'DEM meter input is invalid',
  'meter-io': 'DEM meter storage operation failed',
  'meter-failed': 'DEM meter record failed',
};

/** Convert any hook failure to a fixed, non-sensitive public result. */
export function meterErrorResult(error: unknown): MeterErrorResult {
  const code = error instanceof DemMeterError ? error.code : 'meter-failed';
  return { code, message: METER_ERROR_MESSAGES[code] };
}
