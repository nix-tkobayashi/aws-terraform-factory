variable "log_group_name" {
  description = "Enter CloudWatch Logs log group name. Default is CloudTrail/DefaultLogGroup"
  default     = "CloudTrail/DefaultLogGroup"
}

variable "email" {
  description = "Email address to notify when an API activity has triggered an alarm"
}
