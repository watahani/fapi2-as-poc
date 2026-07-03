/**
 * AuthZEN Authorization API PDP adapter (HTTP). The AS is the PEP; it POSTs an
 * Access Evaluation request to an external decision point (OPA/Topaz/Cedar/…)
 * and reads back the boolean `decision`. Fails CLOSED: any transport error,
 * non-2xx, or malformed body yields decision=false so a PDP outage cannot
 * grant access.
 *
 * Request/response shapes follow the AuthZEN Authorization API evaluation
 * model (subject/action/resource/context → { decision, context? }).
 */
import type {
  EvaluationRequest,
  EvaluationResponse,
  PolicyDecisionPoint,
} from "../pdp.js";

export interface AuthZenHttpOptions {
  /** Full evaluation endpoint URL (e.g. https://pdp/access/v1/evaluation). */
  url: string;
  /** Optional bearer token for authenticating to the PDP. */
  token?: string;
  /** Request timeout (ms). */
  timeoutMs?: number;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export class AuthZenHttpPdp implements PolicyDecisionPoint {
  private readonly url: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: AuthZenHttpOptions) {
    this.url = opts.url;
    this.token = opts.token || undefined;
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async evaluate(req: EvaluationRequest): Promise<EvaluationResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
        body: JSON.stringify({
          subject: req.subject,
          action: req.action,
          resource: req.resource,
          ...(req.context ? { context: req.context } : {}),
        }),
        signal: controller.signal,
      });
      if (!res.ok) return { decision: false, context: { reason: `pdp-http-${res.status}` } };
      const body = (await res.json()) as { decision?: unknown; context?: Record<string, unknown> };
      // Only an explicit boolean true grants access (fail closed on anything else).
      if (body.decision !== true) return { decision: false, context: body.context };
      return { decision: true, context: body.context };
    } catch (err) {
      // Timeout / network / malformed JSON — deny.
      return { decision: false, context: { reason: `pdp-error:${(err as Error).name}` } };
    } finally {
      clearTimeout(timer);
    }
  }
}
