/**
 * Amazon CloudWatch コントロール
 * https://docs.aws.amazon.com/ja_jp/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-3
 *
 * Center for Internet Security (CIS) AWS Foundations Benchmark v1.2.0 および v1.4.0
 * https://docs.aws.amazon.com/ja_jp/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
 *
 * cf.
 * https://dev.classmethod.jp/articles/setting-aws-cis-foundations-benchmark-monitoring-with-awscli/
 */

resource "aws_sns_topic" "alarm_notification" {
  name = "AlarmNotificationTopic"
}

resource "aws_sns_topic_subscription" "email_sub" {
  topic_arn = aws_sns_topic.alarm_notification.arn
  protocol  = "email"
  endpoint  = var.email
}

/**
 * [CloudWatch.1] 「ルート」ユーザーの使用に対するログメトリクスフィルターとアラームが存在する必要があります
 */
resource "aws_cloudwatch_log_metric_filter" "root_user_event" {
  name           = "RootUserEventMetricFilter"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "RootUserEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_user_event_alarm" {
  alarm_name          = "RootUserActivity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootUserEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.2] 不正な API 呼び出しに対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "authorization_failures" {
  name           = "AuthorizationFailuresMetricFilter"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "AuthorizationFailureCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "authorization_failures_alarm" {
  alarm_name          = "CloudTrailAuthorizationFailures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "AuthorizationFailureCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.3] MFA を使用しないマネジメントコンソールサインインに対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_logins_event" {
  name           = "NoMfaConsoleLoginsEventMetricFilter"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "NoMfaConsoleLoginEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_console_logins_event_alarm" {
  alarm_name          = "ConsoleSigninWithoutMFA"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NoMfaConsoleLoginEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.4] IAM ポリシーの変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes_metric_filter" {
  name           = "IAMPolicyChangesMetricFilter"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "IAMPolicyEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes_alarm" {
  alarm_name          = "CloudTrailIAMPolicyChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IAMPolicyEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.5] CloudTrail AWS Config 設定の変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "CloudTrailChangesMetricFilter"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "CloudTrailEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes_alarm" {
  alarm_name          = "CloudTrailChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "CloudTrailEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.6] AWS Management Console 認証の失敗に対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "console_sign_in_failures" {
  name           = "ConsoleSignInFailuresMetricFilter"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "ConsoleSignInFailureCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_sign_in_failures_alarm" {
  alarm_name          = "CloudTrailConsoleSignInFailures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleSignInFailureCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "3"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.7] カスタマーマネージドキーの無効化またはスケジュールされた削除に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "kms_disabled_or_scheduled_deletion_event" {
  name           = "KmsDisabledOrScheduledDeletionEventMetricFilter"
  pattern        = "{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "KmsDisabledOrScheduledDeletionEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_disabled_or_scheduled_deletion_event_alarm" {
  alarm_name          = "CIS3.7_KmsDisabledOrScheduledDeletion"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KmsDisabledOrScheduledDeletionEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.8] S3 バケットポリシーの変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_change_event" {
  name           = "S3BucketPolicyChangeEventMetricFilter"
  pattern        = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "S3BucketPolicyChangeEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_change_event_alarm" {
  alarm_name          = "S3BucketPolicyChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "S3BucketPolicyChangeEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.9] AWS Config 設定の変更に対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "aws_config_change_event" {
  name           = "AWSConfigChangeEventMetricFilter"
  pattern        = "{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "AWSConfigChangeEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_change_event_alarm" {
  alarm_name          = "CIS3.9_AWSConfigChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "AWSConfigChangeEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.10] セキュリティグループの変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "security_group_changes_metric_filter" {
  name           = "SecurityGroupChangesMetricFilter"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "SecurityGroupEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes_alarm" {
  alarm_name          = "CloudTrailSecurityGroupChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityGroupEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.11] ネットワークアクセスコントロールリスト (NACL) への変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "network_acl_changes_metric_filter" {
  name           = "NetworkAclChangesMetricFilter"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "NetworkAclEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_acl_changes_alarm" {
  alarm_name          = "CloudTrailNetworkAclChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NetworkAclEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.12] ネットワークゲートウェイへの変更に対するログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "gateway_changes_metric_filter" {
  name           = "GatewayChangesMetricFilter"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "GatewayEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "gateway_changes_alarm" {
  alarm_name          = "CloudTrailGatewayChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "GatewayEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.13] ルートテーブルの変更に対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "route_table_change_event" {
  name           = "RouteTableChangeEventMetricFilter"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = var.log_group_name

  metric_transformation {
    name      = "RouteTableChangeEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_change_event_alarm" {
  alarm_name          = "RouteTableChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RouteTableChangeEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}

/**
 * [CloudWatch.14] VPC の変更に対してログメトリクスフィルターとアラームが存在することを確認します
 */
resource "aws_cloudwatch_log_metric_filter" "vpc_changes_metric_filter" {
  name           = "VpcChangesMetricFilter"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "VpcEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes_alarm" {
  alarm_name          = "CloudTrailVpcChanges"
  alarm_description   = "Alarms when an API call is made to create, update or delete a VPC, VPC peering connection or VPC connection to classic."
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
  metric_name         = "VpcEventCount"
  namespace           = "CloudTrailMetrics"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "1"
}

/**
 * ★
 */
/*
resource "aws_cloudwatch_log_metric_filter" "ec2_instance_changes" {
  name           = "EC2InstanceChangesMetricFilter"
  pattern        = "{ ($.eventName = RunInstances) || ($.eventName = RebootInstances) || ($.eventName = StartInstances) || ($.eventName = StopInstances) || ($.eventName = TerminateInstances) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "EC2InstanceEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2_instance_changes_alarm" {
  alarm_name          = "CloudTrailEC2InstanceChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "EC2InstanceEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}
*/

/**
 * ★
 */
/*
resource "aws_cloudwatch_log_metric_filter" "ec2_large_instance_changes" {
  name           = "EC2LargeInstanceChangesMetricFilter"
  pattern        = "{ ($.eventName = RunInstances) && (($.requestParameters.instanceType = *.8xlarge) || ($.requestParameters.instanceType = *.4xlarge)) }"
  log_group_name = var.log_group_name

  metric_transformation {
    namespace = "CloudTrailMetrics"
    name      = "EC2LargeInstanceEventCount"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2_large_instance_changes_alarm" {
  alarm_name          = "CloudTrailEC2LargeInstanceChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "EC2LargeInstanceEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "SampleCount"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.alarm_notification.arn]
}
*/
