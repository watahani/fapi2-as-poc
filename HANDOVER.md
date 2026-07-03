# HANDOVER — FAPI 2.0 認可サーバー PoC

P1（コアプロトコル自前実装）完了時点の引継ぎ。詳細設計は [docs/GOALS.md](docs/GOALS.md) / [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) / [docs/SPECS.md](docs/SPECS.md)、要件トレーサビリティは [docs/REQUIREMENTS-P1.md](docs/REQUIREMENTS-P1.md) を参照。

## 1. これは何か / 現状

- 目的：**FAPI 2.0 Security Profile 準拠の認可サーバーをスクラッチ実装**できるかの実証実験。既存 OAuth/OIDC ライブラリは不使用（許容は jose / Fastify / pg / zod / pino のみ）。
- 最終ゴール：**FAPI2 SP Conformance Suite を green + 1 vCPU/800MB で 100 RPS**、認証・認可・プロトコルが分離された構成。
- 現状：**P1 完了**。プロトコル本体を実装済み：
  - **エンドポイント**：`/.well-known/openid-configuration`・`/.well-known/oauth-authorization-server`・`/jwks`・`/par`・`/authorize`・`/token`・`/revoke`・`/introspect`（+ `/health`・`/healthz`）。
  - **フロー**：PAR (RFC 9126) → authorize + PKCE S256 (RFC 7636) + iss (RFC 9207) → token（private_key_jwt (RFC 7523) + DPoP (RFC 9449)）→ JWT AT (RFC 9068) + ID Token (OIDC) + refresh（ローテーションなし）→ revocation (RFC 7009) / introspection (RFC 7662)。
  - **鍵**：ES256 DB keystore（自動生成・`npm run keys:rotate`・秘密鍵は KEYSTORE_KEK で AES-256-GCM 暗号化）。
  - **認証委譲の継ぎ目**：`src/domain/interaction.ts`（P1 は dev 自動認証、P2 で外部 IdP へ）。consent は AuthZEN PDP（`src/authz/`）。
  - **in-repo conformance（Layer 1）が 20/20 green**。CI（`npm run test:conformance`）ゲート化済み。unit 134 / typecheck / prod-audit も green。
- 認証は P1 では dev 自動認証（`DEV_INTERACTION_SUB`）。**本番投入前の必須事項は §6 次フェーズ参照**（実ユーザー認証・セッション束縛・consent UI）。
- セキュリティ：各 PR で code-review + security-review ループ実施、**Critical/High/Medium = 0**（既知の PoC スコープ逸脱は docs/REQUIREMENTS-P1.md §14 と各 PR に記録）。

## 2. 構成（要点）

```
.devcontainer/   Claude Code サンドボックス（host 隔離 + iptables/ipset egress 許可リスト）
src/             Fastify(HTTP) / config(zod) / db(pg+自前マイグレーション) / 分離境界(endpoints,domain,crypto,authz)
deploy/helm/auth-server/   k8s Helm chart（AS + dev postgres + NetworkPolicy 雛形, requests=limits 1cpu/800Mi）
scripts/         dev-cluster.sh(in-sandbox k3s) / check-allowlist-sync.sh
Dockerfile       アプリ本番イメージ（multi-stage, digest ピン留め）
.github/workflows/ci.yml   typecheck/test/prod-audit/SBOM/helm lint/allowlist 同期
```

- **隔離**：ホスト FS/認証情報は非マウント。egress は許可リスト（anthropic / npm / GitHub / 仕様ソース / Conformance / レジストリ）のみ。`init-firewall.sh` が権威、`managed-settings.json` と同期（`scripts/check-allowlist-sync.sh` で機械チェック）。
- **k8s**：サンドボックス内 k3s（単体 / DinD なし / privileged）。イメージは nerdctl ビルド → `ctr import`。
- **DB**：PostgreSQL を一次ストア（Redis は P4 で必要時）。

## 3. Dev 環境のテスト手順（すべてサンドボックス内）

### 3.1 隔離の確認
```bash
curl -sS https://api.anthropic.com/ -o /dev/null -w '%{http_code}\n'   # 到達OK
curl -sS https://example.com/ --max-time 5 || echo "BLOCKED (期待通り)"  # 遮断される
cat ~/.ssh/* 2>&1 | head -1                                            # アクセス不可（期待通り）
```

### 3.2 アプリ単体
```bash
npm install
npm run typecheck     # 0 エラー
npm test              # health スモーク 2/2
npm run dev           # DATABASE_URL を起動中の postgres に向ける（未起動なら /healthz は db:down=503）
```

### 3.3 k8s（in-sandbox k3s + Helm）
```bash
bash scripts/dev-cluster.sh up                 # k3s 起動（privileged）
nerdctl build -t auth-server:dev .             # 本番イメージ（Docker デーモン不使用）
bash scripts/dev-cluster.sh import auth-server:dev
helm install as deploy/helm/auth-server -n as --create-namespace
kubectl -n as port-forward svc/as-auth-server 3000:3000 &
curl -s localhost:3000/healthz                 # postgres 起動後 {"status":"ok","db":"up"}
```

### 3.4 マイグレーション
```bash
npm run migrate        # migrations/*.sql を順次適用（自前ランナー）
```

## 4. バージョン管理：jj (Jujutsu) を git の代わりに使用

このプロジェクトは **git ではなく jj** で管理する。jj はサンドボックスにインストール済み（Dockerfile に追加。未反映なら §4.1）。jj は既存の `.git` と**コロケート**運用する（git とも相互運用可能）。

> なぜ jj：git の `commit.gpgsign=true` が非対話環境で pinentry 待ちハングを起こしていたが、**jj は git の gpgsign 設定を読まず既定で署名しない**ため、この問題を回避できる。

### 4.1 （未反映の場合のみ）今すぐ jj を入れる
Dockerfile をまだリビルドしていない場合、起動中コンテナに即インストール：
```bash
JJ=0.42.0; A=x86_64
curl -fsSL "https://github.com/jj-vcs/jj/releases/download/v${JJ}/jj-v${JJ}-${A}-unknown-linux-musl.tar.gz" \
  | sudo tar -xz -C /tmp && sudo mv /tmp/jj /usr/local/bin/jj && jj --version
```
（恒久化は「Rebuild Container」で Dockerfile の jj が焼き込まれる）

### 4.2 初期化（既存 git リポにコロケート）
```bash
jj git init --colocate          # 既存 .git を取り込み、.jj を併設
jj config set --repo user.name  "Wataru Haniyama"
jj config set --repo user.email "wataru.haniyama@authlete.com"
```
> 現状 git コミットは未作成（過去の commit は gpg ハングで中断）。コロケート後、作業ツリーが最初の変更 `@` として取り込まれる。

### 4.3 基本ワークフロー
```bash
jj st                            # 状態（作業コピーは自動でスナップショット）
jj describe -m "chore: P0 dev environment + skeleton (FAPI2 AS PoC)"  # 現在の変更に説明
jj new                           # 次の変更を開始
jj log                           # 履歴
jj diff                          # 変更差分
```
- **コミットメッセージは Conventional Commits**（`feat:` / `fix:` / `chore:` …）を維持。
- ステージング概念は無い：作業コピー全体が常に `@`（現在の変更）に入る。

### 4.4 ブランチ = bookmark / リモート push
```bash
jj git remote add origin <REPO_URL>
jj bookmark create feature/p1-par -r @     # フィーチャーブランチ相当
jj git push --bookmark feature/p1-par      # push → PR を作成
```
- **main への直 push 禁止**（グローバル規約）。bookmark を切って push → PR 経由でマージ。
- 署名が必要なら：`jj config set --repo signing.backend gpg` ＋ `jj config set --repo signing.behavior own`（pinentry 非対話に注意。CI/サンドボックスでは無署名推奨）。

## 5. 既知の注意点

- **k3s は privileged 必須**（in-sandbox / DinD なし）。コンテナを信頼境界とみなす設計（host 隔離 + egress 制限済み）。起動不可ならフォールバック（サンドボックス内 postgres プロセス + Helm 静的検証）を docs/GOALS §9 で相談。
- **in-sandbox k3s の snapshotter**：overlayfs-on-overlayfs が不可（`failed to mount overlay: invalid argument`）でノードが登録されない。`scripts/dev-cluster.sh` は `--snapshotter=fuse-overlayfs`（イメージに同梱）で起動するよう修正済み。**注意：起動中の k3s は root 所有で、`sudo` は `k3s/nerdctl/ctr/init-firewall.sh` のみ NOPASSWD のため `pkill` 不可＝再起動できない**。誤った snapshotter で起動済みの場合はコンテナ rebuild でリセット。kubeconfig は `sudo k3s kubectl config view --raw` で取得（`sudo cat` はパスワードを要求し不可）。
- **Conformance Suite イメージ**：`conformance-image.yml` が upstream `release-v5.1.45` を GitHub Actions でビルド→`ghcr.io/watahani/conformance-suite-{server,httpd}:pinned`（**現状 private**）へ push、かつ tarball を artifact 出力。GHCR を public 化するには packages スコープ付きトークン/UI 操作が必要（gh の現トークンは未付与）。CI（`conformance.yml`）は `GITHUB_TOKEN` で private のまま pull 可。k3s では artifact を `gh run download` → `sudo k3s ctr images import`（`deploy/conformance/k8s/suite.yaml` 参照）。
- **Conformance 実走状況**：**in-repo Layer 1（`npm run test:conformance`）は 20/20 green で CI ゲート化済み**。外部 OpenID Conformance Suite（Layer 2, `conformance.yml`）は P3 で本有効化：discovery/PAR/authorize/token が実装済みになったので、次は suite の FAPI2 SP プラン（DPoP + private_key_jwt）を回し、browser interaction（authorize リダイレクト）を dev 自動認証で通す配線が残タスク。
- **firewall の egress 許可リスト**は `init-firewall.sh` が権威。ドメイン追加時は `managed-settings.json` も更新し `scripts/check-allowlist-sync.sh` を通す（CI でも検査）。解決失敗は必須ドメインのみ FATAL、他は WARN。
- **migrate の .sql** は tsc が dist にコピーしないため `npm run migrate`（tsx）前提。本番 Job 化は P3+。0002 に P1 ドメインスキーマ（signing_keys / par_requests / grants / authorization_codes / access_tokens / refresh_tokens / jti_replay）。
- **dev 依存（vitest/esbuild）の audit advisory** は本番イメージに含まれない（multi-stage で prune）。本番依存は脆弱性 0。
- **`.env` ファイルはセキュリティ保護で作成不可**。環境変数は README の表 / k8s ConfigMap+Secret で与える。
- Helm の DB パスワードは**コミットしない**：未指定なら既存 Secret 再利用 or ランダム生成。

## 6. 次フェーズ（P2 以降）

- **P2 認証委譲 + PDP 統合**：`src/domain/interaction.ts` の dev 自動認証を外部 IdP 連携へ差し替え、**実ユーザー認証・セッション束縛・consent UI**を実装（P1 のセキュリティレビューで「本番前必須」と指摘済み）。prompt=none/max_age/acr_values を実 auth_time に対して評価。AuthZEN PDP を実体（OPA/Topaz/Cedar）に接続（`PDP_KIND=authzen-http`）。
- **P3 Conformance Suite 通過**：外部 suite を FAPI2 SP プランで green に（browser interaction 配線）。
- **P4 性能**：100 RPS / 1vCPU / 800MB・`/token` p95 <50ms を計測。鍵/JWKS/クライアントのキャッシュ（Redis 後付け）でボトルネック解消。
- **本番前ゲート（レビュー由来）**：private_key_jwt 秘密鍵の envelope 暗号化は実装済みだが **KEYSTORE_KEK を KMS/sealed-secret 管理**へ。`resource` パラメータ (RFC 8707) で AT の `aud` をリソース別に絞る（現状は issuer 既定）。DB 接続 TLS（`DATABASE_SSL=true`、本番ガードで強制）。

## 7. クイックリファレンス

| やりたいこと | コマンド |
|---|---|
| 型チェック | `npm run typecheck` |
| テスト | `npm test` |
| conformance (Layer 1) | `npm run test:conformance` |
| 鍵ローテーション | `npm run keys:rotate` |
| クライアント投入 | `npm run seed:clients -- clients.json` |
| ローカル起動 | `npm run dev` |
| k3s 起動/停止 | `bash scripts/dev-cluster.sh up` / `down` |
| Helm デプロイ | `helm install as deploy/helm/auth-server -n as --create-namespace` |
| 許可リスト同期確認 | `bash scripts/check-allowlist-sync.sh` |
| 変更を記録(jj) | `jj describe -m "..."` → `jj new` |
