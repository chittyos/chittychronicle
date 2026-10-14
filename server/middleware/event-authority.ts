import type { Request, Response, NextFunction } from 'express';

type EventRequest = Request & { chittyActorId?: string };

export function requireEventActor(req: EventRequest, res: Response, next: NextFunction) {
  const actorId = (req.header('x-chitty-actor-id') || '').trim();
  if (!actorId) {
    return res.status(400).json({
      error: 'Event actor identity is required',
      code: 'MISSING_EVENT_ACTOR',
    });
  }
  req.chittyActorId = actorId;
  return next();
}

export function requireEventCaseBody(req: Request, res: Response, next: NextFunction) {
  const caseId = typeof req.body?.caseId === 'string' ? req.body.caseId.trim() : '';
  if (!caseId) {
    return res.status(400).json({
      error: 'Event matter/case identity is required',
      code: 'MISSING_EVENT_CASE',
    });
  }
  return next();
}

export function requireEventCaseQuery(req: Request, res: Response, next: NextFunction) {
  const caseId = typeof req.query?.caseId === 'string' ? req.query.caseId.trim() : '';
  if (!caseId) {
    return res.status(400).json({
      error: 'Event matter/case identity is required',
      code: 'MISSING_EVENT_CASE',
    });
  }
  return next();
}
