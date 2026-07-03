# FAPI 2.0 Conformance ハーネス

FAPI 2.0 Security Profile（+ DPoP + private_key_jwt）を検証する仕組み。**2 レイヤ**構成：

- **Layer 1（in-repo・常時実行可）**：`npm run test:conformance`。AS を `buildApp()` で起動し HTTP で叩いて FAPI2 SP 要件を直接アサート（Docker/外部 suite 不要）。仕様要件を実行可能な形で表現した高速フィードバック層。エンドポイント未実装のうちは **red**（P1 の TDD ベースライン）。実体は `test/conformance/fapi2-sp.test.ts`。
- **Layer 2（external・P3 で本有効化）**：OpenID Foundation の **Conformance Suite** を prebuilt イメージで起動し外部から当てる（以下）。

## 方式（毎回ビルドしない / ローカルも簡単に）

Suite は **一度だけビルドして GHCR に publish**（`.github/workflows/conformance-image.yml`・たまに実行）し、**CI もローカルも pull するだけ**。被テストの AS をサービス起動 → 外部から Suite を当てる（eudiplo の e2e/conformance CI 構成を参考）。

| 実行場所 | 起動方法 | 理由 |
|---|---|---|
| **ローカル（サンドボックス）** | `bash run-local.sh` → **k3s** に `k8s/suite.yaml` を apply | devcontainer に **Docker デーモンは無い**（k3s+containerd, DinD なし）。k3s が prebuilt を pull |
| **CI / Docker があるホスト** | `docker compose -f docker-compose.yml up` | GitHub runner には docker あり。prebuilt を pull |

どちらも **per-run ビルド無し**（prebuilt を pull するだけ）。

## レジストリ / 認証

- Suite イメージ（`conformance-suite-server` / `-httpd`）は **GHCR に public で公開**する前提 → **pull 認証不要**（ローカル k3s も CI もそのまま pull）。
- CI の `GITHUB_TOKEN` でのログインは private 化した場合の保険として残置（public なら不要）。
- AS の push 等の GitHub 認証は **SSH エージェント転送**（PAT 不要）。詳細は [CLAUDE.md](../../CLAUDE.md) の「GitHub 認証」。

## 構成ファイル

| ファイル | 役割 |
|---|---|
| `k8s/suite.yaml` | ローカル（k3s）用：mongodb / server / httpd の Deployment+Service（prebuilt イメージ） |
| `docker-compose.yml` | CI / Docker ホスト用：同じ prebuilt イメージを compose で起動 |
| `run-local.sh` | サンドボックスのワンコマンド：k3s に apply → port-forward → `run-conformance.sh` |
| `run-conformance.sh` | 稼働中 Suite（`$SUITE_URL`）に FAPI2 SP プランを `test-config.json` で実行 |
| `test-config.json` | テストプラン設定（issuer/discovery・client・variant: private_key_jwt + dpop + PAR）テンプレート |
| `results/` | 実行結果（CI で artifact 化。gitignore） |

## 有効化ステータス

- **Layer 1（in-repo）**: 実装済み・実行可能。`npm run test:conformance` で走り、エンドポイント未実装のため現状 **red**（18 中ほぼ全て fail）。これが「FAPI conformance を実行して失敗する」状態。CI では gated な `conformance.yml` の最初のステップで実行。
- **Layer 2（external OpenID Suite）**: **`conformance.yml`（runner）で FAPI2 SP final プランを AS に対して end-to-end 実走し、P1 の到達可能範囲を green 化**。
  - **イメージは publish 済み**：`conformance-image.yml` が upstream `release-v5.1.45` をビルドし、`ghcr.io/watahani/conformance-suite-{server,httpd}:pinned`（GHCR private）へ push、かつ tarball を artifact 出力。
  - **構成**（`docker-compose.yml`）：suite（mongodb/server/httpd）+ AS + postgres を同一 docker ネットワークで起動。AS は `https://as:8443` を自己署名 TLS（`gen-certs.sh`）で提供し、suite server は CA を PKCS12 truststore で信頼。静的クライアント（`conformance-client.json`、公開 JWKS + suite callback、対応秘密鍵は `test-config.json`）を `seed:clients` で投入。認可リダイレクトは dev 自動認証で即 303 するため、`run-conformance.sh` が WAITING 時にヘッドレス Chromium（`drive-browser.mjs`）で追従して flow を完了。
  - **実走結果（P1 完了時点・overall=PASS）**：**48 PASSED / 2 SKIPPED / 6 想定 non-pass**（`run-conformance.sh` は想定 non-pass で run を落とさない）。
    - discovery-endpoint-verification、happy-flow、DPoP（proof/jkt/nonce/iat/ath・mismatch 各種）、PKCE（必須・不正 verifier・plain 拒否）、PAR（aud/audience 各種・invalid method・duplicate params）、client-assertion（aud/exp/sub 各種）、refresh、期限切れ auth code 拒否、userinfo(RS DPoP) などが PASS。
    - **想定 non-pass（`EXPECTED_NONPASS`）は 2 種**：
      1. **対話系（P2 で解消）**：`user-rejects-authentication`（ユーザーが拒否する必要）、`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`（初回訪問で認証を完了しない必要）。P1 の dev 自動認証（常に承認・即認証）では原理的に生成できない → P2（外部 IdP 委譲 + consent UI）。
      2. **非リダイレクトのエラーページ（harness 制約）**：`ensure-unsigned-authorization-request-without-using-par-fails` / `par-attempt-reuse-request_uri` / `par-attempt-to-use-expired-request_uri` / `par-attempt-to-use-request_uri-for-different-client`。AS は（信頼できる redirect_uri が無いため）正しく **400 エラーページ**で拒否するが、suite は callback 経由でしか結果を観測できず、外部ヘッドレスブラウザに返るエラーページを検出できないため WAITING になる。**AS の拒否挙動は Layer 1（`test/conformance/fapi2-sp.test.ts` + unit）で直接アサート済み**。
    - SKIPPED：`test-claims-parameter-identity-claims`（claims パラメータ設定が任意）、`ensure-signed-client-assertion-with-RS256-fails`（テスト鍵が EC のため suite が RS256 assertion を生成できずスキップ。AS 側は ES256/PS256/EdDSA のみ受理で RS256 は拒否）。
  - **sandbox k3s 実走は当面不可**：`--snapshotter=fuse-overlayfs` 必須（`dev-cluster.sh` 修正済み）だが起動中 k3s を再起動できず（sudo 制約）本セッションでは不可。rebuild で解消。private GHCR は pull 不可なので k3s では tarball を `ctr import`（`k8s/suite.yaml` 参照）。

## 残タスク

1. **P2 で `EXPECTED_NONPASS` の 2 件を解消**：実ユーザー認証・consent UI・拒否パスを実装し、allowlist から外して全モジュール pass を要求する。
2. RS256 client-assertion 拒否を suite でも実行する場合は、テストクライアントに RSA 鍵を追加（AS 側の拒否は Layer 1 で担保済み）。
3. green を CI 必須化（push/PR トリガー追加）。
