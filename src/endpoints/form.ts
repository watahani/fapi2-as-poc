/**
 * application/x-www-form-urlencoded body parser (scratch — no plugin dep).
 * Duplicate parameters are preserved as arrays so the domain layer can
 * reject them (RFC 6749 §3.1/§3.2: parameters MUST NOT be included more
 * than once).
 */
import type { FastifyInstance } from "fastify";

export function registerFormBodyParser(app: FastifyInstance): void {
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string", bodyLimit: 256 * 1024 },
    (_req, body, done) => {
      try {
        // Bound the parameter count: a 256KB body of tiny params would
        // otherwise materialise tens of thousands of object keys per request.
        const raw = body as string;
        if ((raw.match(/&/g)?.length ?? 0) >= 256) {
          const err = new Error("too many form parameters") as Error & { statusCode: number };
          err.statusCode = 400;
          throw err;
        }
        // Null-prototype object + own-property checks: a "__proto__" (or
        // "constructor") form field must not pollute the body's prototype.
        const out: Record<string, unknown> = Object.create(null);
        for (const [key, value] of new URLSearchParams(raw)) {
          const existing = Object.hasOwn(out, key) ? out[key] : undefined;
          if (existing === undefined) {
            out[key] = value;
          } else if (Array.isArray(existing)) {
            existing.push(value);
          } else {
            out[key] = [existing, value];
          }
        }
        done(null, out);
      } catch (err) {
        done(err as Error);
      }
    },
  );
}
