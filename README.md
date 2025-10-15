# Cowrie Detector 🕵️‍♂️ (v4.2)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

Cowrieハニーポットを、複数の指標に基づいて高精度に検出するためのPythonスクリプトです。

---
## 概要

`cowrie_detector.py`は、ターゲットのSSHサーバーが人気のハニーポット「Cowrie」であるかどうかを特定する分析ツールです。ハニーポットの研究者やペネトレーションテスターが、調査対象が本物のシステムか、巧妙に仕掛けられた罠かを見分ける手助けをします。

このツールは、単に設定ファイルの内容をチェックするだけでなく、Cowrie特有の**防御的な振る舞い**をあぶり出す「**ハイブリッド分析エンジン**」を搭載しており、堅牢化されたCowrieも見抜くことが可能です。

---
## 主な機能

* **ハイブリッド分析**: 自動化ツールを検知して接続を切断するCowrieの防御反応（`Channel closed`）を検出しつつ、その裏をかいて対話形式のシェルで内部情報を調査します。
* **高度なスコアリング**: 各指標を「一般的なサーバーでも起こり得るか？」という基準で点数付けし、ターゲットがCowrieであることの信頼性をスコアで提示します。
* **詳細な結果表示**: 信頼スコアに応じて、「デフォルト設定のCowrie」なのか「意図的に運用されているCowrie」なのか、分析結果を分かりやすくコメントします。
* **レガシー暗号方式のサポート**: デフォルトのCowrieが`root`ログインで要求する、古い暗号方式での接続を試みるロジックを搭載しています。

---
## インストール (Ubuntu)

このツールは、Pythonの仮想環境（`venv`）上に構築することを強く推奨します。これにより、お使いのシステムの他のPythonプロジェクトに影響を与えることなく、安全にライブラリを管理できます。

0.  **OS更新**
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

1.  **前提ソフトウェアをインストールします。**
    `git`や`python3-venv`など、ツールを実行するために必要なシステムパッケージをインストールします。
    ```bash
    sudo apt install -y git python3-venv python3-pip libssl-dev libffi-dev build-essential
    ```

2.  **リポジトリをダウンロードします。**
    ```bash
    git clone https://github.com/mizuna-honeypot/cowrie_detector.git
    ```

3.  **ディレクトリに移動します。**
    ```bash
    cd cowrie_detector
    ```

4.  **Python仮想環境を作成します。**
    `detecter-env`という名前の仮想環境が作成されます。
    ```bash
    python3 -m venv detecter-env
    ```

5.  **仮想環境を有効化します。**
    プロンプトの先頭に`(detecter-env)`と表示されれば成功です。
    ```bash
    source detecter-env/bin/activate
    ```

6.  **必要なPythonライブラリをインストールします。**
    ```bash
    pip install --upgrade pip
    pip install paramiko
    ```

---
## 使い方

ターミナルから以下のように実行します。
    ```bash
    python3 cowrie_detector.py <ターゲットのIPアドレス> [ポート番号]
    ```

**実行例:**

* **ポート番号を省略した場合（デフォルトは22番）**
    ```bash
    python3 cowrie_detector.py 192.168.1.100
    ```

* **ポート番号を指定した場合**
    ```bash
    python3 cowrie_detector.py 192.168.1.100 2222
    ```

---
## 注意事項

* このツールは教育および研究目的でのみ使用してください。
* ターゲットのシステムに対してスキャンを行う際は、必ず適切な許可を得てください。不正アクセスは法律で禁じられています。

---
## ライセンス

このプロジェクトは[MITライセンス](LICENSE)の下で公開されています。
