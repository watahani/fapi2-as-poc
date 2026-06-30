import type {
  EvaluationRequest,
  EvaluationResponse,
  PolicyDecisionPoint,
} from "../pdp.js";

/**
 * In-process development PDP. Allows everything by default so the OAuth
 * flow can be exercised before a real AuthZEN PDP is wired in (phase 2).
 * Swap via PDP_KIND=authzen-http to delegate to an external decision point.
 */
export class MockPdp implements PolicyDecisionPoint {
  async evaluate(_req: EvaluationRequest): Promise<EvaluationResponse> {
    return { decision: true, context: { reason: "mock-allow-all" } };
  }
}
