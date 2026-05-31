# kage

Go 言語で開発された、シンプルかつ軽量・高速なプロキシツールです。
ローカルからの複数種類の接続を受け付け、外部のプロキシサーバーへの通信（アウトバウンド）には強力な暗号化通信プロトコルである **Shadowsocks** を採用しています。

## 特徴とアーキテクチャ

本ツールは、柔軟なルーティングとセキュアな通信を提供するために設計されています。

### インバウンド (Inbound: ローカルからの接続受付)
ユーザーのアプリケーション（ブラウザやその他のツール）からの接続を処理します。1つのプロセスで複数のインバウンドを同時に待ち受けることが可能です。
- **SOCKS5**: 汎用的なプロキシプロトコル。TCP に加え、**UDP (Shadowsocks 2022 / SIP022)** にも対応しています。
- **HTTP Proxy**: 一般的な HTTP 通信用のプロキシプロトコル。
- **TCP Tunnel**: ローカルの特定のポートへの接続を、リモートの指定したターゲット（IPとポート）へそのまま転送（ポートフォワーディング）する機能。

### アウトバウンド (Outbound: 外部サーバーへの接続)
- **Shadowsocks**: すべてのアウトバウンドトラフィックは、**Shadowsocks** プロトコルを使用して暗号化され、リモートサーバーへ転送されます。**Shadowsocks 2022** 仕様に準拠した最新の暗号化方式と UDP 転送をサポートしています。

## インストール方法

ソースコードからビルドするには、Go 環境 (1.25 以上) が必要です。

```bash
# リポジトリのクローン
git clone https://github.com/aomori446/kage.git
cd kage

# クライアントのビルド
go build -o kage .
```

## プロジェクト構造

本プロジェクトは、メンテナンス性と拡張性を考慮した 2 層のディレクトリ構造を採用しています。

```text
/kage/
├── main.go            # エントリポイント
├── config.go          # 設定読み込み
├── logger.go          # ログ初期化
├── core/              # 共通基盤 (Address, Relay)
├── shadowsocks/       # Shadowsocks プロトコル実装
├── socks5/            # SOCKS5 プロトコル実装
├── http/              # HTTP プロキシ実装
└── tunnel/            # TCP トンネル実装
```

## 使い方

設定ファイル (`config.json`) を指定してプログラムを起動します。

```bash
./kage -c config.json
```

## 設定ファイル仕様 (`config.json`)

設定は JSON 形式で行います。以下はクライアント側の設定例です。

```json
{
  "server": "example.com:8388",
  "method": "2022-blake3-aes-128-gcm",
  "password": "BASE64_ENCODED_PASSWORD_HERE",
  "log_level": "info",
  "inbounds": [
    {
      "type": "socks5",
      "listen": "127.0.0.1:1080",
      "fast_open": true,
      "udp": true
    },
    {
      "type": "http",
      "listen": "127.0.0.1:8080"
    },
    {
      "type": "tunnel",
      "listen": "127.0.0.1:5432",
      "target": "10.0.0.2:5432"
    }
  ]
}
```

### パラメータの説明

- `server`: 接続先となるリモートの Shadowsocks サーバーのアドレスとポート (`IP:Port`)。
- `method`: Shadowsocks の暗号化方式。
  - Shadowsocks 2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`
  - 従来方式: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- `password`: Shadowsocks サーバーのパスワード（PSK）。**注意:** 設定ファイルには Base64 でエンコードされた文字列を記述する必要があります。
- `log_level`: ログの出力レベル (`debug`, `info`, `warn`, `error`)。
- `inbounds`: リッスンするローカルポートとプロトコルの配列。
  - `type`: `socks5`, `http`, `tunnel` のいずれか。
  - `listen`: ローカルで待ち受けるアドレスとポート (`IP:Port`)。
  - `target`: `type` が `tunnel` の場合のみ必須。転送先の最終目的地 (`IP:Port`)。
  - `fast_open`: (オプション) TCP Fast Open を有効にする場合は `true`。
  - `udp`: (オプション) `socks5` において UDP 転送を有効にする場合は `true`。

## ライセンス

MIT License
