# FAPI 2.0 認可サーバー PoC（スクラッチ実装）

「Claude Code を使って **FAPI 2.0 Security Profile 準拠の認可サーバーをスクラッチ実装できるか**」を検証する実証実験。既存 OAuth/OIDC ライブラリは使わず、プロトコルロジックを自前実装する。

- ゴール定義: [docs/GOALS.md](docs/GOALS.md)
- アーキテクチャ: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 仕様トレーサビリティ: [docs/SPECS.md](docs/SPECS.md)

## 方針サマリ

| 項目 | 採用 |
|---|---|
| ランタイム | Node.js 24 / TypeScript / ESM |
| 許容ライブラリ | jose（暗号）/ Fastify（HTTP）/ pg（生SQL）/ zod / pino /（Redis は後付け） |
| 一次ストア | PostgreSQL（本番稼働スペックのため DB 必須） |
| Sender-constraining | DPoP 先行（mTLS は後続） |
| 開発環境 | Claude Code Docker サンドボックス（ホスト隔離 + egress 許可リスト） |
| デプロイ | k8s ネイティブ（Helm chart）。ローカルは in-sandbox k3s（DinD なし） |

## 開発環境（サンドボックス）

全開発は Claude Code の Docker サンドボックス内で行う。ホスト FS/認証情報は非マウント、egress は許可リスト（`api.anthropic.com` / npm / GitHub / 仕様ソース / Conformance / レジストリ）のみ。

1. VS Code 等で本リポジトリを開き「Reopen in Container」（`.devcontainer/` を使用）。
2. 起動時に `init-firewall.sh` が egress 許可リストを適用する（非許可ドメインは遮断）。

詳細・許可ドメインは `.devcontainer/Dockerfile` / `.devcontainer/init-firewall.sh` を参照。

## ローカル実行（サンドボックス内）

```bash
npm install
npm run typecheck          # 型チェック
npm test                   # health スモークテスト

# ローカル k8s（k3s 単体・DinD なし）+ Helm デプロイ
bash scripts/dev-cluster.sh up
nerdctl build -t auth-server:dev .
bash scripts/dev-cluster.sh import auth-server:dev
helm install as deploy/helm/auth-server -n as --create-namespace
kubectl -n as port-forward svc/as-auth-server 3000:3000 &
curl -s localhost:3000/healthz   # {"status":"ok","db":"up",...}

# マイグレーション（DATABASE_URL を起動中の postgres に向ける）
npm run migrate
```

ローカル開発で k8s を介さず直接動かす場合は `npm run dev`（`DATABASE_URL` を起動中の PostgreSQL に向ける）。

## 環境変数

`.env.example` はセキュリティ保護により作成不可のため、ここに一覧を集約する。実行時は環境変数 / k8s ConfigMap+Secret で与える。

| 変数 | 既定値 | 説明 |
|---|---|---|
| `PORT` | `3000` | リッスンポート |
| `ISSUER` | `https://localhost:3000` | issuer 識別子 |
| `LOG_LEVEL` | `info` | pino ログレベル |
| `DATABASE_URL` | `postgresql://authserver:devpassword@localhost:5432/authserver` | PostgreSQL 接続文字列 |
| `DATABASE_SSL` | `false` | `true` で PostgreSQL への TLS（証明書検証あり）を有効化 |
| `NODE_ENV` | （空） | `production` 時は mock PDP / localhost issuer / 既定 DATABASE_URL を拒否 |
| `PDP_KIND` | `mock` | 認可判断 PDP（`mock` / `authzen-http`） |
| `PDP_AUTHZEN_URL` | `http://localhost:8080/access/v1/evaluation` | AuthZEN PDP エンドポイント |
| `PDP_AUTHZEN_TOKEN` | （空） | PDP 呼び出し用トークン |
| `REDIS_URL` | （空） | キャッシュ（後付け・空=無効） |
| `EXTERNAL_IDP_URL` | （空） | 認証委譲先 IdP（P2・空=組込み dev interaction） |

## ディレクトリ構成

```
.devcontainer/        Claude Code サンドボックス（Dockerfile / devcontainer.json / init-firewall.sh / managed-settings.json）
deploy/helm/auth-server/  k8s Helm chart（AS + dev postgres + NetworkPolicy 雛形）
scripts/dev-cluster.sh    in-sandbox k3s 管理（up/down/status/import）
Dockerfile            アプリ本番イメージ（multi-stage, node:24-slim）
src/
  index.ts            Fastify buildApp（/health, /healthz）
  config.ts           設定（zod 検証）
  endpoints/          OAuth/OIDC/FAPI エンドポイント境界（P1）
  domain/             プロトコルロジック自前実装（P1）
  crypto/             jose ラッパ（P1）
  authz/              AuthZEN PDP 境界 + mock
  db/                 pg プール + 自前マイグレーションランナー + migrations/
test/                 vitest
```

## ステータス

P0（開発環境 + 骨組み）完了。P1 以降で FAPI2 プロトコル本体を実装する。フェーズ計画は [docs/GOALS.md](docs/GOALS.md) を参照。
