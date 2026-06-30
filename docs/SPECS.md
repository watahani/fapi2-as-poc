# 仕様トレーサビリティ（Source of Trust）

本 PoC では **RFC / FAPI 仕様を一次情報源（Source of Trust）** とする。実装は仕様の該当箇所を参照しながら行い、仕様で一意に決まらない点・仕様に記載のない非機能要件は人間と相談して決める。

## 対象仕様

| 仕様 | 用途 |
|---|---|
| FAPI 2.0 Security Profile (final) | 全体プロファイル・制約の根拠 |
| FAPI 2.0 Attacker Model | 脅威モデル |
| RFC 6749 / 6750 | OAuth 2.0 / Bearer |
| RFC 7636 | PKCE (S256) |
| RFC 9126 | Pushed Authorization Requests (PAR) |
| RFC 9449 | DPoP（proof / nonce / jkt） |
| RFC 7521 / 7523 | private_key_jwt クライアント認証（JWT assertion） |
| RFC 7515 / 7517 / 7518 / 7519 | JWS / JWK / JWA / JWT |
| RFC 9068 | JWT profile for OAuth access tokens |
| OIDC Core / Discovery | ID Token / メタデータ |
| RFC 8414 | Authorization Server Metadata |
| RFC 9207 | Authorization response `iss` |
| RFC 7662 / 7009 | Introspection / Revocation（任意） |
| RFC 9101 | JAR（任意） |
| AuthZEN Authorization API | 認可判断（PDP）連携 |

## 機能 → 仕様 マッピング（実装トレーサビリティ）

| 機能 | 主仕様 | 実装場所（予定） |
|---|---|---|
| PAR | RFC 9126 | `src/endpoints` + `src/domain/par` |
| authorize + PKCE | RFC 6749 / 7636 | `src/endpoints` + `src/domain/pkce` |
| token（code/refresh） | RFC 6749 | `src/domain/grant` |
| DPoP | RFC 9449 | `src/domain/dpop` + `src/crypto` |
| private_key_jwt | RFC 7521/7523 | `src/domain/client-auth` + `src/crypto` |
| JWT access token / cnf | RFC 9068 | `src/domain/token` + `src/crypto` |
| Discovery / JWKS | RFC 8414 / OIDC | `src/endpoints` + `src/crypto` |
| iss パラメータ | RFC 9207 | `src/domain` |
| FAPI2 SP 制約 | FAPI 2.0 SP | `src/domain/fapi2` |

> 仕様本文の取得は egress 許可リスト（ietf.org / rfc-editor.org / openid.net）経由でサンドボックス内から行う。
> 実装時は該当 RFC のセクション番号をコード/コミットに引用し、判断根拠を追跡可能にする。
