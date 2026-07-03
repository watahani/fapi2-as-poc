# P1 要件トレーサビリティ — FAPI 2.0 コアプロトコル

P1 実装が満たすべき規範要件の列挙（Source of Trust = 仕様本文、2026-07-02 取得）。
各要件に ID を振り、テスト（`test/conformance/`・unit）とコード・コミットから ID / 仕様セクションで引用する。

- 出典: FAPI 2.0 Security Profile final / FAPI 2.0 Attacker Model final（openid.net）、
  RFC 6749 / 6750 / 7009 / 7521 / 7523 / 7636 / 7662 / 8414 / 9068 / 9126 / 9207 / 9449 / 9700、
  OIDC Core 1.0 (errata set 2) / OIDC Discovery 1.0（rfc-editor.org / openid.net）。
- 本 AS のプロファイル: **FAPI 2.0 SP + DPoP + private_key_jwt + PAR + authorization_code / refresh_token のみ**。
  mTLS / Message Signing / JARM / RFC 9101 JAR はスコープ外（P5+）。
- 表記: `shall/must` 要件は無印、`should` は **(S)**、`may`（実装判断）には **(M)** を付す。

## 1. FAPI2-* — FAPI 2.0 Security Profile（AS 要件）

### 一般（§5.3.2.1）
| ID | 要件 | 出典 |
|---|---|---|
| FAPI2-GEN-1 | Discovery メタデータを OIDD / RFC 8414 の文書で配布する | 5.3.2.1(1) |
| FAPI2-GEN-2 | resource owner password credentials grant を拒否する | 5.3.2.1(2) |
| FAPI2-GEN-3 | confidential client のみサポートする | 5.3.2.1(3) |
| FAPI2-GEN-4 | sender-constrained なアクセストークンのみ発行する | 5.3.2.1(4) |
| FAPI2-GEN-5 | sender-constraining は mTLS (RFC 8705) または DPoP (RFC 9449)。本 AS は DPoP | 5.3.2.1(5) |
| FAPI2-GEN-6 | クライアント認証は mTLS または private_key_jwt (OIDC §9)。本 AS は private_key_jwt | 5.3.2.1(6) |
| FAPI2-GEN-7 | open redirector を公開しない | 5.3.2.1(7), RFC9700 §4.11 |
| FAPI2-GEN-8 | クライアント認証 assertion の `aud` は **issuer 識別子の文字列のみ**受理（token endpoint URL・配列は拒否） | 5.3.2.1(8) |
| FAPI2-GEN-9 | リフレッシュトークンのローテーションは行わない（特段の事情を除く） | 5.3.2.1(9) |
| FAPI2-GEN-10 | (M) DPoP server-provided nonce 機構を使用してよい（実装するが既定 off） | 5.3.2.1(10) |
| FAPI2-GEN-11 | authorization code の寿命は **最大 60 秒** | 5.3.2.1(11) |
| FAPI2-GEN-12 | DPoP 使用時、Authorization Code Binding to DPoP Key（`dpop_jkt`, RFC 9449 §10.1）をサポートする | 5.3.2.1(12) |
| FAPI2-GEN-13 | JWT の `iat`/`nbf` は未来方向 0–10 秒まで許容してよいが、**60 秒超の未来は拒否** | 5.3.2.1(13) |
| FAPI2-GEN-14 | (S) アクセストークンの権限は用途に必要な最小限に制限する | 5.3.2.1(14) |

### Authorization code flow（§5.3.2.2）
| ID | 要件 | 出典 |
|---|---|---|
| FAPI2-AUTHZ-1 | `response_type=code` を必須とする | 5.3.2.2(1) |
| FAPI2-AUTHZ-2 | クライアント認証付き PAR (RFC 9126) をサポートする | 5.3.2.2(2) |
| FAPI2-AUTHZ-3 | PAR を経由しない authorization request を拒否する | 5.3.2.2(3) |
| FAPI2-AUTHZ-4 | クライアント認証のない pushed authorization request を拒否する | 5.3.2.2(4) |
| FAPI2-AUTHZ-5 | PKCE (RFC 7636) を `S256` で必須とする | 5.3.2.2(5) |
| FAPI2-AUTHZ-6 | PAR リクエストに `redirect_uri` を必須とする | 5.3.2.2(6) |
| FAPI2-AUTHZ-7 | authorization response に `iss` (RFC 9207) を返す | 5.3.2.2(7) |
| FAPI2-AUTHZ-8 | authorization response を非暗号化接続で送らない。`http` スキーム redirect URI 禁止（native loopback 例外, RFC 8252 §7.3） | 5.3.2.2(8) |
| FAPI2-AUTHZ-9 | 使用済み authorization code を拒否する | 5.3.2.2(9) |
| FAPI2-AUTHZ-10 | ユーザー資格情報を含むリクエストのリダイレクトに HTTP 307 を使わない | 5.3.2.2(10) |
| FAPI2-AUTHZ-11 | (S) user agent のリダイレクトに HTTP 303 を使う | 5.3.2.2(11) |
| FAPI2-AUTHZ-12 | PAR `request_uri` の `expires_in` は **600 秒未満** | 5.3.2.2(12) |
| FAPI2-AUTHZ-13 | (S) informed consent に必要な情報（クライアント・scope）をエンドユーザーに提供する | 5.3.2.2(13) |
| FAPI2-AUTHZ-14 | OIDC サポート時、64 文字までの `nonce` を受理する（超過は拒否可） | 5.3.2.2(14) |
| FAPI2-AUTHZ-15 | (S) request_uri の one-time use / 期限消費は「authorization action 時」に行う（ページロードで消費しない） | 5.3.2.2 NOTE 3 |
| FAPI2-USER-1 | ユーザー識別子をクライアントへ返す場合は OIDC（ID Token）による | 5.3.2.3(1) |

### 暗号・鍵（§5.4）
| ID | 要件 | 出典 |
|---|---|---|
| FAPI2-CRYPTO-1 | JWT の作成・処理は RFC 8725 (JWT BCP) に従う | 5.4.1(1a) |
| FAPI2-CRYPTO-2 | 署名アルゴリズムは **PS256 / ES256 / EdDSA (Ed25519)** のみ。`none` は使用も受理も禁止 | 5.4.1(1b)(1c) |
| FAPI2-CRYPTO-3 | RSA ≥2048bit / EC ≥224bit / 自動生成秘密 ≥128bit エントロピー | 5.4.1(2)(3)(4) |
| FAPI2-CRYPTO-4 | jwks_uri は TLS のみで提供 | 5.4.2(1) |
| FAPI2-CRYPTO-5 | (S) `x5u`/`jku` JOSE ヘッダを使わない。JWKS 内で `kid` を重複させない | 5.4.2(2)(3) |
| FAPI2-CRYPTO-6 | `kid` 重複時は他属性（kty/use/alg/crv）で検証鍵を選択する | 5.4.3 |
| FAPI2-TLS-1 | 全エンドポイント TLS 1.2+/BCP195（デプロイ層の責務。アプリは https URL のみ広告） | 5.2.1, 5.2.2 |
| FAPI2-TLS-2 | **authorization endpoint に CORS を設定しない** | 5.2.3(3) |

### セキュリティ考慮（§6）
| ID | 要件 | 出典 |
|---|---|---|
| FAPI2-SEC-1 | (S) アクセストークンは短寿命にする | §6.1 |
| FAPI2-SEC-2 | DPoP proof リプレイを jti 追跡（/nonce）で緩和する | §6.2 |
| FAPI2-SEC-3 | client_id がエンドユーザー識別子と混同されないようにする | §6.7, RFC9068 §5 |
| FAPI2-SEC-4 | 鍵ローテーションを可能な設計にする（kid 運用） | §6.8 |

## 2. PAR-* — RFC 9126 Pushed Authorization Requests

| ID | 要件 | 出典 |
|---|---|---|
| PAR-1 | PAR エンドポイントは https。クライアント認証は token endpoint と同一規則 | §2 |
| PAR-2 | 処理順: (1) client 認証 → (2) `request_uri` パラメータが含まれていたら拒否 → (3) authorization request として検証（redirect_uri 登録照合・scope 認可） | §2.1 |
| PAR-3 | 成功時 **HTTP 201** + JSON `{request_uri, expires_in}`、`Cache-Control: no-cache, no-store` | §2.2 |
| PAR-4 | `request_uri` は暗号学的に推測不能な乱数部を含む。形式は `urn:ietf:params:oauth:request_uri:<ref>` | §2.2, §7.1 |
| PAR-5 | `request_uri` は push したクライアントに束縛する | §2.2 |
| PAR-6 | (S) `request_uri` は one-time use（リロード起因の重複は許容可） | §4, §7.3 |
| PAR-7 | 期限切れ `request_uri` は拒否する | §4 |
| PAR-8 | エラーは RFC 6749 §5.2 形式。`invalid_client` は 401 可。`access_denied` は返さない | §2.3 |
| PAR-9 | 非 POST → **405**、過大リクエスト → **413**、レート超過 → **429** | §2.3 |
| PAR-10 | authorize 側: PAR 必須ポリシー下で `request_uri` の無いリクエストは `invalid_request` | §4 |
| PAR-11 | authorize の `client_id` は request_uri を push したクライアントと一致すること | §2.2+§4 |
| PAR-12 | authorization request としての検証を（push 時に省略した分含め）authorize 時に完了する | §2.1, §4 |
| PAR-13 | metadata: `pushed_authorization_request_endpoint` / `require_pushed_authorization_requests: true` | §5 |
| PAR-14 | 未登録 redirect_uri の受理は認証済みクライアントに限る（本 AS は登録値完全一致のみ運用） | §7.2 |

## 3. PKCE-* — RFC 7636

| ID | 要件 | 出典 |
|---|---|---|
| PKCE-1 | S256: `code_challenge == BASE64URL(SHA256(ASCII(code_verifier)))`（padding なし） | §4.2, §4.6 |
| PKCE-2 | `code_verifier` は unreserved 文字 43–128 文字。文法違反は拒否 | §4.1 |
| PKCE-3 | S256 をサーバー側 MTI として実装。`plain` は不使用（FAPI2 で禁止） | §4.2, §7.2 |
| PKCE-4 | `code_challenge` 欠落（PKCE 必須プロファイル）→ authorization エラー `invalid_request` | §4.4.1 |
| PKCE-5 | 未サポートの `code_challenge_method` → `invalid_request` | §4.4.1 |
| PKCE-6 | code 発行時に `code_challenge`/`code_challenge_method` を code に関連付けて保存する | §4.4 |
| PKCE-7 | token で `code_verifier` を検証。不一致は **`invalid_grant`** | §4.5, §4.6 |
| PKCE-8 | downgrade 防止: `code_verifier` あり ⇔ `code_challenge` あり を相互必須化 | RFC 9700 §2.1.1 |
| PKCE-9 | metadata: `code_challenge_methods_supported: ["S256"]` | RFC 8414 §2 |

## 4. ISS-* — RFC 9207

| ID | 要件 | 出典 |
|---|---|---|
| ISS-1 | **エラー応答を含む**すべての authorization response に `iss` パラメータを含める | §2 |
| ISS-2 | `iss` 値 = RFC 8414 issuer 識別子（https・query/fragment なし）。metadata の `issuer`、ID Token の `iss` と同一 | §2, §2.4 |
| ISS-3 | metadata: `authorization_response_iss_parameter_supported: true` | §3 |

## 5. DPOP-* — RFC 9449

### proof 構造・検証
| ID | 要件 | 出典 |
|---|---|---|
| DPOP-1 | proof は `DPoP` ヘッダの JWT 1 個。header: `typ: dpop+jwt` / `alg`（非対称・none 禁止）/ `jwk`（公開鍵のみ） | §4.1, §4.2 |
| DPOP-2 | claims: `jti`（≥96bit 乱数相当の一意値）/ `htm` / `htu`（query/fragment 除外）/ `iat`（+ RS では `ath`、nonce 供給後は `nonce`） | §4.2 |
| DPOP-3 | §4.3 検証チェックリストを全項目実装: DPoP ヘッダは 1 個のみ / 単一 well-formed JWT / 必須 claim / typ / alg / `jwk` の鍵で署名検証 / jwk に秘密鍵成分なし / htm 一致 / htu 一致 / nonce 一致 / iat 受容窓 | §4.3 |
| DPOP-4 | (S) htu 比較は RFC 3986 §6.2.2/§6.2.3 の正規化を行ってから比較 | §4.3 |
| DPOP-5 | 未知の header/claim があることのみを理由に拒否しない | §4.2 |
| DPOP-6 | proof の受理窓は生成後短時間（秒〜分）。窓内で同一 jti（同一 URI 文脈）を拒否 | §11.1 |

### token endpoint・トークン束縛
| ID | 要件 | 出典 |
|---|---|---|
| DPOP-7 | DPoP クライアントの token リクエストは全 grant で有効な proof 必須。無効 → 400 `invalid_dpop_proof` | §5 |
| DPOP-8 | AT を proof の公開鍵に束縛: `cnf.jkt` = base64url(RFC 7638 SHA-256 JWK thumbprint) | §6, §6.1 |
| DPOP-9 | token response の `token_type` は **`DPoP`** | §5 |
| DPOP-10 | confidential client の RT は DPoP 束縛しない（client auth で束縛済み） | §5 |
| DPOP-11 | client metadata `dpop_bound_access_tokens: true` のクライアントには DPoP ヘッダなしの token リクエストを拒否 | §5.2 |
| DPOP-12 | introspection response に `cnf.jkt` を含め、`token_type` を含めるなら `DPoP` | §6.2 |

### dpop_jkt / PAR 連携（FAPI2-GEN-12 で必須）
| ID | 要件 | 出典 |
|---|---|---|
| DPOP-13 | `dpop_jkt` パラメータを PAR body で受理し code に関連付け。token 時に proof 鍵 thumbprint と照合、不一致は拒否 | §10, §10.1 |
| DPOP-14 | PAR に `DPoP` ヘッダが来たら §4.3 検証のうえ `dpop_jkt` 提供と同等に扱う。両方あれば一致必須 | §10.1 |

### nonce（実装・既定 off）
| ID | 要件 | 出典 |
|---|---|---|
| DPOP-15 | nonce 要求時: 400 `use_dpop_nonce` + `DPoP-Nonce` 応答ヘッダ。nonce は予測不能な値 | §8 |
| DPOP-16 | proof の `nonce` は供給済み nonce（直近の窓）と一致しなければ拒否 | §8 |
| DPOP-17 | nonce を供給済みのクライアントから nonce なし proof を受理しない（downgrade 防止） | §11.3 |
| DPOP-18 | metadata: `dpop_signing_alg_values_supported`（ES256 含む） | §5.1 |

## 6. PKJWT-* — RFC 7521/7523 private_key_jwt（+ FAPI2 上書き）

| ID | 要件 | 出典 |
|---|---|---|
| PKJWT-1 | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion`（JWT は 1 個のみ） | 7523 §2.2, 7521 §4.2 |
| PKJWT-2 | `client_id` パラメータは任意。あれば assertion の subject と一致必須 | 7521 §4.2 |
| PKJWT-3 | 複数のクライアント認証方式の併用は拒否 | 7521 §4.2.1, 6749 §2.3 |
| PKJWT-4 | `iss` = `sub` = client_id（単純文字列比較） | 7523 §3(1)(2), 7521 §6.1 |
| PKJWT-5 | `aud` は issuer 識別子の文字列のみ受理（FAPI2-GEN-8。7523 の token endpoint URL 許容を上書き） | FAPI2 5.3.2.1(8), 7523 §3(3) |
| PKJWT-6 | `exp` 必須。期限切れ拒否（skew 許容は FAPI2-GEN-13 準拠）。過度に遠い exp は拒否（上限を設定） | 7523 §3(4) |
| PKJWT-7 | `nbf`/`iat` があれば検証（FAPI2-GEN-13 の未来方向規則含む） | 7523 §3(5)(6) |
| PKJWT-8 | `jti` リプレイ防止: exp までの窓で使用済み jti を拒否 | 7523 §3(7)(§6), 7521 §8.2 |
| PKJWT-9 | 未知 claim を理由に拒否しない | 7523 §3(8) |
| PKJWT-10 | 署名はクライアント登録 JWKS で検証。無効署名は拒否。alg は ES256/PS256/EdDSA のみ | 7523 §3(9), FAPI2 5.4.1 |
| PKJWT-11 | assertion 不正のエラーは **`invalid_client`**（+ error_description 可） | 7523 §3.2, 7521 §4.2.1 |

## 7. JWTAT-* — RFC 9068 JWT Access Token

| ID | 要件 | 出典 |
|---|---|---|
| JWTAT-1 | 署名必須・`none` 禁止・header `typ: "at+jwt"` | §2.1 |
| JWTAT-2 | 必須 claims: `iss` / `exp` / `aud` / `sub` / `client_id` / `iat` / `jti` | §2.2 |
| JWTAT-3 | `sub` は code grant では resource owner の識別子 | §2.2 |
| JWTAT-4 | `scope` claim（スペース区切り文字列, RFC 8693 §4.2 形式） | §2.2.3 |
| JWTAT-5 | DPoP 束縛 AT に `cnf: {"jkt": ...}`（RFC 7800 §3.1 + RFC 9449 §6.1） | RFC 9449 §6.1 |
| JWTAT-6 | `aud`: `resource` パラメータ未サポートの間は設定のデフォルト resource indicator を必須使用。曖昧な認可の AT は発行しない | §3 |
| JWTAT-7 | auth_time/acr/amr を付与する場合は同一 grant 由来の全 AT で固定値 | §2.2.1 |
| JWTAT-8 | AS 署名は ES256（9068 §2.1 の「RS256 サポート MUST」は FAPI2 専用 AS としての意図的逸脱 → docs に明記） | §2.1, FAPI2 5.4.1 |

## 8. DISC-* — RFC 8414 / OIDC Discovery

| ID | 要件 | 出典 |
|---|---|---|
| DISC-1 | `GET {issuer}/.well-known/openid-configuration`（issuer 末尾 `/` 除去のうえ後置）で 200 / `application/json` | OIDD §4 |
| DISC-2 | RFC 8414 形式 `/.well-known/oauth-authorization-server`（host と path の間に挿入）も提供し内容を一致させる | RFC 8414 §3, RFC 9068 §4 |
| DISC-3 | `issuer` は取得 URL の issuer と完全一致（https・query/fragment なし）。ID Token `iss` とも一致 | RFC 8414 §2 §3.3, OIDD §4.3 |
| DISC-4 | 必須: issuer / authorization_endpoint / token_endpoint / **jwks_uri** / response_types_supported / subject_types_supported / id_token_signing_alg_values_supported | OIDD §3 |
| DISC-5 | 掲載: scopes_supported（`openid` 含む）/ grant_types_supported / token_endpoint_auth_methods_supported（`["private_key_jwt"]`）/ token_endpoint_auth_signing_alg_values_supported（none 禁止）/ code_challenge_methods_supported / pushed_authorization_request_endpoint / require_pushed_authorization_requests / authorization_response_iss_parameter_supported / dpop_signing_alg_values_supported / revocation_endpoint / introspection_endpoint | RFC 8414 §2, 各仕様 |
| DISC-6 | 空配列の claim は応答から省略 | RFC 8414 §3.2 |
| DISC-7 | JWKS は公開鍵のみ（`d` 等の秘密成分・対称鍵を含まない）。各鍵に `kid` | RFC 8414 §2, OIDD §3 |
| DISC-8 | id_token_signing_alg_values_supported は ES256 のみ広告（OIDD の RS256 含有 MUST は FAPI2 専用 AS としての意図的逸脱 → docs に明記） | OIDD §3, FAPI2 5.4.1 |

## 9. OIDC-* — OIDC Core（code flow OP）

| ID | 要件 | 出典 |
|---|---|---|
| OIDC-1 | ID Token 必須 claims: `iss` / `sub`（≤255 ASCII・再割当なし）/ `aud`（client_id）/ `exp` / `iat` | Core §2 |
| OIDC-2 | リクエストに `nonce` があれば ID Token にそのまま含める（他の加工をしない） | Core §2, §3.1.2.1 |
| OIDC-3 | `max_age` 使用時（または essential 要求時）は `auth_time` を含める | Core §2, §3.1.2.1 |
| OIDC-4 | ID Token は JWS 署名（client の `id_token_signed_response_alg`、既定 ES256）。`x5u`/`x5c`/`jku`/`jwk` header 不使用 (S) | Core §2, §3.1.3.7 |
| OIDC-5 | authorization endpoint は GET / POST 両対応 | Core §3.1.2.1 |
| OIDC-6 | `scope=openid` を含むリクエストを OIDC として処理。openid なしは plain OAuth として処理 | Core §3.1.2.2 |
| OIDC-7 | `redirect_uri` は登録値と単純文字列比較で完全一致 | Core §3.1.2.1, RFC 9700 §2.1 |
| OIDC-8 | `prompt=none`: UI 表示禁止。未認証等なら `login_required` 系エラー。`none` と他値の併用は `invalid_request` | Core §3.1.2.1, §3.1.2.3 |
| OIDC-9 | `prompt` / `display` / `ui_locales` / `claims_locales` / `acr_values` / `id_token_hint` / `login_hint` はエラーにしない最低限サポート。`max_age` は再認証を強制 | Core §15.1 |
| OIDC-10 | エラー応答: redirect_uri 無効/client_id 無効時はリダイレクトしない。他は redirect query に `error`（+`error_description`/`state`）。OIDC エラーコード（interaction_required/login_required/consent_required 等）を使用 | Core §3.1.2.6, RFC 6749 §4.1.2.1 |
| OIDC-11 | token response: `application/json` + **`Cache-Control: no-store`**。openid scope の code grant では `id_token` 必須 | Core §3.1.3.3 |
| OIDC-12 | code 引換時: code が当該 client に発行されたこと・有効性・未使用・redirect_uri 同一性・OIDC リクエスト由来であることを検証 | Core §3.1.3.2 |
| OIDC-13 | consent: RP へ情報を返す前に authorization decision を得る（本 AS は PDP 委譲） | Core §3.1.2.4 |
| OIDC-14 | ユーザー対話時は CSRF / クリックジャッキング対策を講じる | Core §3.1.2.3, RFC 6749 §10.12 §10.13 |
| OIDC-15 | subject type は `public` を採用し `subject_types_supported: ["public"]` を広告 | Core §8, OIDD §3 |

## 10. OAUTH-* — RFC 6749/6750 コア

| ID | 要件 | 出典 |
|---|---|---|
| OAUTH-1 | authorization endpoint: 値なしパラメータ = 省略扱い / 未知パラメータ無視 / **同一パラメータの重複禁止** | §3.1 |
| OAUTH-2 | `response_type` 欠落・未知 → §4.1.2.1 エラー | §3.1.1 |
| OAUTH-3 | redirect_uri は絶対 URI・fragment なし | §3.1.2 |
| OAUTH-4 | 成功応答: redirect query に `code` + `state`（リクエストにあれば正確に同値で必須） | §4.1.2 |
| OAUTH-5 | code は client と redirect_uri に束縛。再利用は拒否し、**当該 code 起源の発行済みトークンを失効** | §4.1.2, §10.5 |
| OAUTH-6 | token endpoint: POST のみ / `application/x-www-form-urlencoded` / パラメータ重複禁止 / 未知パラメータ無視 | §3.2 |
| OAUTH-7 | confidential client は token endpoint（および同規則の PAR/revocation/introspection）でクライアント認証必須 | §3.2.1 |
| OAUTH-8 | code 引換検証: client 一致 / code 有効 / redirect_uri（authorization request に含まれていた場合）必須かつ同一値 | §4.1.3 |
| OAUTH-9 | 成功 200: `access_token` / `token_type` / `expires_in` (S) / `refresh_token` / `scope`（要求と異なる場合必須） + **`Cache-Control: no-store`**（+`Pragma: no-cache`） | §5.1 |
| OAUTH-10 | エラー 400 JSON: `error`（invalid_request / invalid_client / invalid_grant / unauthorized_client / unsupported_grant_type / invalid_scope）。`invalid_client` は 401 可、Authorization ヘッダ使用時は 401 + `WWW-Authenticate` 必須 | §5.2 |
| OAUTH-11 | refresh grant: client 認証 + RT の client 束縛検証 + RT 有効性検証。scope は元の付与の範囲内のみ（縮小可） | §6 |
| OAUTH-12 | RT・code 等の推測確率 ≤ 2^-128（≥128bit エントロピー）。RT はハッシュ保存 | §10.10, §10.4 |
| OAUTH-13 | `state`・`redirect_uri` 等の入力値をサニタイズ・検証する | §10.14 |
| OAUTH-14 | scope はスペース区切り・大文字小文字区別。省略時は既定値を適用するか invalid_scope | §3.3 |
| OAUTH-15 | （RS 参考）Bearer/DPoP エラーモデル: 401 `WWW-Authenticate`、invalid_request(400)/invalid_token(401)/insufficient_scope(403) | 6750 §3.1 |

## 11. REV-* / INTR-* — RFC 7009 / 7662

| ID | 要件 | 出典 |
|---|---|---|
| REV-1 | revocation endpoint: POST + client 認証（token endpoint と同一規則）。RT の失効サポート必須、AT も失効可 (S) | 7009 §2, §2.1 |
| REV-2 | `token` 必須 + `token_type_hint` 任意（hint で見つからなければ全種検索。無効な hint 値は無視） | 7009 §2.1, §2.2 |
| REV-3 | 他クライアントに発行されたトークンは失効させない。列挙オラクル回避のため、不明トークンと同様に **200 で no-op**（RFC 7009 §2.1 の反列挙意図に沿う実装判断） | 7009 §2.1 |
| REV-4 | **無効・不明トークンでも 200** を返す | 7009 §2.2 |
| REV-5 | RT 失効時は同一 grant の AT も失効させる (S)。AT 失効時の RT 失効は (M) | 7009 §2.2 |
| REV-6 | `unsupported_token_type` エラーをサポート | 7009 §2.2.1 |
| REV-7 | token endpoint 同等の防御（レート制限等）を適用 | 7009 §5 |
| INTR-1 | introspection endpoint: POST + 呼出元の認証・認可必須（P1 は client 認証、自クライアントのトークンのみ） | 7662 §2.1, §4 |
| INTR-2 | 応答 200 JSON: `active` 必須。inactive の場合は理由等の追加情報を返さない | 7662 §2.2 |
| INTR-3 | `active: true` の前に exp / nbf / 失効状態 / 署名 / audience の全チェックを実施 | 7662 §4 |
| INTR-4 | active 応答に scope / client_id / token_type / exp / iat / sub / aud / iss / jti、DPoP AT は `cnf.jkt`（token_type は `DPoP`） | 7662 §2.2, 9449 §6.2 |
| INTR-5 | 呼出元の認証失敗は 401 | 7662 §2.3 |

## 12. BCP-* — RFC 9700 OAuth Security BCP（6749 既定の上書き）

| ID | 要件 | 出典 |
|---|---|---|
| BCP-1 | redirect_uri は **exact string matching**（部分一致・パターン一致禁止） | §2.1 |
| BCP-2 | ROPC (`password` grant) は使用禁止 | §2.4 |
| BCP-3 | PKCE をサポートし、downgrade を防止（PKCE-8） | §2.1.1 |
| BCP-4 | 資格情報を含む POST 後のリダイレクトは 303（307 禁止） | §2.1, §4.12 |
| BCP-5 | `http` スキームの redirect URI 禁止（native loopback 例外） | §2.6 |
| BCP-6 | CORS を authorization endpoint でサポートしない（token/jwks/metadata は可） | §2.6 |
| BCP-7 | クライアントに `client_id` を自由に決めさせない（ユーザー識別子との混同防止） | §2.6, §4.15 |
| BCP-8 | AT は audience 制限し (S)、最小権限とする | §2.3 |

## 13. NFR-* — 非機能要件（CLAUDE.md 指定の検討項目）

| ID | 要件 | P1 での扱い |
|---|---|---|
| NFR-1 | トークンローテーション UI / 管理機能 | DB スキーマ（jti/grant 単位管理）+ revocation/introspection で土台。UI/管理 API は P2+ |
| NFR-2 | FAPI Security Profile 選択（sender-constraining / client auth 切替） | client metadata（token_endpoint_auth_method / dpop_bound_access_tokens）で設計。mTLS は P5 |
| NFR-3 | トークン管理（一覧・失効・introspection 連携） | AT/RT を jti・ハッシュで DB 管理。失効 = REV-*、参照 = INTR-* |
| NFR-4 | 鍵管理・ローテーション | DB keystore（active/retired kid）+ `npm run keys:rotate`。KMS/k8s Secret は後続 |
| NFR-5 | 監査ログ | pino 構造化イベント（client auth 成否・PAR/code/token 発行・失効） |
| NFR-6 | レート制限 | PAR-9 の 429 対応の簡易 in-memory 制限。本格化は P4 |
| NFR-7 | 性能目標 1vCPU / 800MB / 100RPS・/token p95 < 50ms | P4 で計測。P1 は鍵キャッシュ・往復削減の設計のみ |

## 14. プロファイル上の意図的逸脱（要文書化）

| 項目 | 逸脱内容 | 根拠 |
|---|---|---|
| RS256 | OIDD §3・OIDC Core §15.1・RFC 9068 §2.1 は RS256 サポートを MUST とするが、本 AS は ES256 のみ | FAPI2 5.4.1 が PS256/ES256/EdDSA に制限。FAPI2 専用 AS であり汎用 OIDC/9068 認定は非目標 |
| client assertion `aud` | RFC 7523 §3(3) は token endpoint URL を許容するが、issuer 識別子の文字列のみ受理 | FAPI2 5.3.2.1(8)（rfc7523bis も同方向） |
| RT ローテーション | RFC 6749 §10.4 は rotation を例示するが、行わない | FAPI2 5.3.2.1(9)。sender-constraining は client auth 束縛で充足（RFC 9700 §2.2.2） |
| `plain` PKCE | RFC 7636 §4.2 は plain を定義するが不使用・拒否 | FAPI2 5.3.2.2(5) |
