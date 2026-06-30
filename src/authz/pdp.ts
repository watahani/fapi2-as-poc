/**
 * Policy Decision Point (PDP) boundary.
 *
 * The authorization server acts as a PEP and delegates authorization
 * decisions (consent, scope grant, resource access) to a PDP that speaks
 * the OpenID AuthZEN Authorization API. This interface keeps the protocol
 * engine independent of any concrete PDP (OPA / Topaz / Cedar / mock).
 *
 * Shapes follow the AuthZEN Access Evaluation request/response model.
 */

export interface AuthZenSubject {
  readonly type: string;
  readonly id: string;
  readonly properties?: Record<string, unknown>;
}

export interface AuthZenResource {
  readonly type: string;
  readonly id: string;
  readonly properties?: Record<string, unknown>;
}

export interface AuthZenAction {
  readonly name: string;
  readonly properties?: Record<string, unknown>;
}

export interface EvaluationRequest {
  readonly subject: AuthZenSubject;
  readonly action: AuthZenAction;
  readonly resource: AuthZenResource;
  readonly context?: Record<string, unknown>;
}

export interface EvaluationResponse {
  readonly decision: boolean;
  readonly context?: Record<string, unknown>;
}

export interface PolicyDecisionPoint {
  evaluate(req: EvaluationRequest): Promise<EvaluationResponse>;
}
