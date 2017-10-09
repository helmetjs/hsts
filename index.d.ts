import { Request, Response, Handler } from 'express';

export interface HstsOptions {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
    setIf?: (req: Request, res: Response) => boolean;
}

export function hsts(options?: HstsOptions): Handler;
