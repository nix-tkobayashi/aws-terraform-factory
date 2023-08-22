# AWS Security Monitoring Terraform Project

このTerraformプロジェクトは、AWSのセキュリティ設定を監視し、不正なアクティビティが検出された場合に通知を送信するためのものです。

## 機能

- AWSのCloudTrailログから特定のイベントをフィルタリングし、それらのイベントを監視します。具体的には、以下のようなイベントが監視対象となっています：

|No|説明|アラーム名|
|---|---|---|
|1|ルートユーザーの使用|RootUserActivity|
|2|APIの認証エラー|CloudTrailAuthorizationFailures|
|3|MFAを使用せずにコンソールにサインインする行為|ConsoleSigninWithoutMFA|
|4|IAMポリシーの変更|IAMPolicyChangesMetricFilter|
|5|CloudTrailの設定変更|CloudTrailChanges|
|6|マネジメントコンソールの認証失敗|CloudTrailConsoleSignInFailures|
|7|KMSキーの無効化またはスケジュールされた削除|CIS3.7_KmsDisabledOrScheduledDeletion|
|8|S3バケットポリシーの変更|S3BucketPolicyChanges|
|9|AWS Configの設定変更|CIS3.9_AWSConfigChanges|
|10|セキュリティグループの変更|CloudTrailSecurityGroupChanges|
|11|ネットワークアクセスコントロールリスト（NACL）の変更|CloudTrailNetworkAclChanges|
|12|ネットワークゲートウェイの変更|CloudTrailGatewayChanges|
|13|ルートテーブルの変更|RouteTableChanges|
|14|VPCの変更|CloudTrailVpcChanges|
|15|AWS Organizationsの変更|CloudTrailOrganizationsChanges|

- 監視対象のイベントが検出された場合に、AWSのSNS (Simple Notification Service) を使用して通知を送信します。

## 事前条件

- AWSアカウント
- Terraformがインストールされていること

## インストール方法

1. このリポジトリをクローンまたはダウンロードします。
2. `variables.tf` ファイルで、必要な変数を設定します。
3. `terraform init` を実行してプロジェクトを初期化します。
4. `terraform apply` を実行してプロジェクトをデプロイします。

## 使用方法

- デプロイ後、AWS CloudTrailログの監視が開始されます。
- 監視対象のイベントが検出されると、設定したメールアドレスに通知が送信されます。

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています。

## 著者

nix-tkobayashi
