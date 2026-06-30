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
- **Layer 2（external OpenID Suite）**: **配線完了・runner で実走確認済み**。
  - **イメージは publish 済み**：`conformance-image.yml` が upstream `release-v5.1.45` を自前 GitHub Actions でビルドし、`ghcr.io/watahani/conformance-suite-{server,httpd}:pinned`（GHCR private）へ push、かつ tarball を artifact 出力。
  - **runner 実走（`conformance.yml`）で end-to-end 検証済み**：suite イメージを private GHCR から pull → 起動 → `run-conformance.sh` が discovery ゲートで `exit 1`（= P1 未実装による正当な **red**）。`PASS` には P1（PAR/authorize/token/DPoP/JWKS/Discovery）が必要。
  - **sandbox k3s 実走は当面不可**：in-sandbox k3s は overlayfs-on-overlayfs 不可で `--snapshotter=fuse-overlayfs` が必須（`dev-cluster.sh` 修正済み）だが、起動中 k3s は root 所有・`sudo` が k3s/nerdctl/ctr のみ NOPASSWD のため**再起動できず**、本セッションでは k3s 経路を実走できなかった。コンテナ rebuild で解消。private GHCR は pull 不可なので k3s では artifact tarball を `ctr import` する（`k8s/suite.yaml` 参照）。

## P3 で確定させる TODO

1. `conformance-image.yml` で upstream（`gitlab.com/openid/conformance-suite`）の **pin tag** を確定し、server/httpd を build & push（GHCR public）。`k8s/suite.yaml` と `docker-compose.yml` の `image:` を digest で固定。
2. テストプラン名（例 `fapi2-security-profile-final-test-plan`）と variant（fapi_profile / client_auth_type / sender_constrain / fapi_request_method）を確定。
3. `run-conformance.sh` の自動化（Suite API で plan 作成→実行→結果取得、非 PASS で fail）を完成。
4. 認可リダイレクト時のテストユーザー認証（外部 IdP スタブ）を用意。
5. green を P0 一行ゴールの達成条件として CI 必須化（push/PR トリガー追加）。
