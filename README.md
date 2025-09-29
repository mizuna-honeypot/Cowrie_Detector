Cowrie Detector
Cowrieハニーポットを検出するための、シンプルかつ強力なPythonスクリプトです。

概要
cowrie_detector.pyは、指定されたSSHサーバーが人気のハニーポット「Cowrie」であるかどうかを、複数の指標に基づいて分析・特定するツールです。ハニーポットの研究者や、ペネトレーションテストの初期調査などで、ターゲットが本物のシステムか、あるいは巧妙に仕掛けられた罠かを見分ける手助けをします。

このツールは、以下のようなCowrie特有の「指紋（フィンガープリント）」をチェックします。

SSHバナー: Cowrieがデフォルトで使用するSSHのバージョン情報。

認証情報: root:rootやphil:philのような、よく知られたデフォルトの認証情報でログインを試みます。

システムの振る舞い: ログイン成功後のコマンド実行時の不自然な挙動（Channel closedエラーなど）を検出します。

システム情報: uname -aやcat /etc/passwdコマンドの実行結果から、Cowrieのデフォルト設定の痕跡を探します。

特徴
高精度な検出: 複数の指標を組み合わせることで、Cowrieを高い信頼度で検出します。

シンプル: Python3とparamikoライブラリのみで動作し、複雑なセットアップは不要です。

カスタマイズ可能: スクリプト内の認証情報のリストなどを簡単に編集し、独自のテストパターンを追加できます。

分かりやすい結果表示: 検出された指標と、それがどの程度確からしいかを示す信頼度（Confidence Level）をパーセンテージで表示します。

必要なもの
Python 3.x

paramiko ライブラリ

インストール
リポジトリをクローンします。

Bash

git clone https://github.com/あなたのユーザー名/cowrie_detector.git
cd cowrie_detector
必要なライブラリをインストールします。

Bash

pip install paramiko
使い方
ターミナルから以下のように実行します。

Bash

python3 cowrie_detector.py <ターゲットのIPアドレス> [ポート番号]
実行例:

ポート番号を省略した場合（デフォルトは22番）

Bash

python3 cowrie_detector.py 192.168.1.100
ポート番号を指定した場合

Bash

python3 cowrie_detector.py 18.183.96.194 2222
実行結果の例
============================================================
SCAN RESULTS
============================================================
[!] COWRIE HONEYPOT DETECTED!
[!] Confidence Level: 95%

[+] Detected Indicators:
    1. Weak credentials accepted: admin:admin
    2. No basic commands work after authentication
    3. Default Cowrie user 'phil' found in /etc/passwd
    4. Typical Cowrie kernel version detected: 3.2.0-4-amd64

[!] HIGH CONFIDENCE: This is very likely a Cowrie honeypot
============================================================
注意事項
このツールは教育および研究目的でのみ使用してください。

ターゲットのシステムに対してスキャンを行う際は、必ず適切な許可を得てください。不正アクセスは法律で禁じられています。

ライセンス
このプロジェクトはMITライセンスの下で公開されています。
