# kage

Go で書かれたシンプルで軽量なプロキシツール。

## 特徴

- **マルチインバウンド対応**: SOCKS5, HTTP, TCP ターネル。
- **暗号化通信**: セキュアなデータ転送。
- **簡単な設定**: JSON 形式での構成。

## インストール

```bash
git clone https://github.com/aomori446/kage.git
cd kage
go build -o kage ./cmd/kage-client
```

## 使い方

```bash
./kage -c config.json
```

## 設定例 (config.json)

```json
{
  "server": "server_address:port",
  "method": "aes-128-gcm",
  "password": "BASE64_ENCODED_KEY",
  "log_level": "info",
  "inbounds": [
    {
      "type": "socks5",
      "listen": "127.0.0.1:1080"
    }
  ]
}
```

## ライセンス

MIT
