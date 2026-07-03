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
- **Layer 2（external OpenID Suite）**: **P1 完了後の runner 実走で「suite が公式 FAPI2 SP final プランを AS に対して生成」まで到達**。
  - **イメージは publish 済み**：`conformance-image.yml` が upstream `release-v5.1.45` をビルドし、`ghcr.io/watahani/conformance-suite-{server,httpd}:pinned`（GHCR private）へ push、かつ tarball を artifact 出力。
  - **runner 実走（`conformance.yml`）で確認済みの動作**（P1 完了時点）：
    1. suite（mongodb/server/httpd）が起動（`docker-compose.yml` に server の起動 env = devmode + OIDC ダミーを追加して 502 を解消）。
    2. `run-conformance.sh` が AS discovery を取得（**discovery ゲート通過** — P1 前はここで red）。
    3. Suite API で **`fapi2-security-profile-final-test-plan`（openid_connect + private_key_jwt + dpop, plain_fapi）を作成成功（HTTP 201, 57 モジュール）**。variant は plan が固定する `fapi_request_method`/`fapi_response_mode` を送らず、必須の `openid` を指定。
  - **green までの残タスク**（下記 TODO 1–3）：モジュール実行には suite→AS 到達性・**FAPI が要求する AS の TLS**・**静的クライアント登録**が必要。
  - **sandbox k3s 実走は当面不可**：`--snapshotter=fuse-overlayfs` 必須（`dev-cluster.sh` 修正済み）だが起動中 k3s を再起動できず（sudo 制約）本セッションでは不可。rebuild で解消。private GHCR は pull 不可なので k3s では tarball を `ctr import`（`k8s/suite.yaml` 参照）。

## green までの残タスク（P3）

1. **suite→AS 到達性 + TLS**：suite の server コンテナから AS へ到達させる（compose 内に AS を同一ネットワークで起動 等）。FAPI は AS の **https** を要求するため、AS を自己署名 TLS で提供し suite の truststore に信頼させる（または suite の TLS 検証設定を調整）。ISSUER の https 化に伴い `src/index.ts` に任意 TLS を追加。
2. **静的クライアント登録**：suite が使うクライアント鍵（`test-config.json` の `client.jwks` に秘密鍵）と対応する公開 JWKS・`redirect_uris`（`https://<suite>/test/a/<alias>/callback`）を AS に `npm run seed:clients` で投入。動的登録は未実装（P2+）。
3. **認可インタラクション**：本 AS は dev 自動認証（UI なし）で `/authorize` が即 303 → code。suite の自動ブラウザがリダイレクトを追えるか確認し、必要なら調整。
4. green を CI 必須化（push/PR トリガー）。
