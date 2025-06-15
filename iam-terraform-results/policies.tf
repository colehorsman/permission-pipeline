data "aws_iam_policy_document" "firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE_document" {
  version = "2012-10-17"
  statement {
    effect    = "Deny"
    actions   = ["acm-pca:DescribeCertificateAuthorityAuditReport", "athena:BatchGetQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:GetQueryResultsStream", "athena:ListQueryExecutions", "auditmanager:*", "braket:Search*", "cassandra:*", "chime:GetApp*", "chime:ListChannel*", "chime:ListChannels*", "chime:DescribeChannel*", "chime:ListApp*", "chime:DescribeApp*", "chime:GetUser*", "chime:ListMeeting*", "chime:ListMeetings*", "chime:GetMeeting", "chime:GetChannel*", "chime:ListGroups", "chime:GetPhoneNumber", "chime:GetSipMedia*", "chime:GetAccount*", "chime:ListDirectories", "chime:ListDomains", "chime:GetMessagingSessionEndpoint", "chime:ListUsers", "chime:GetProxySession", "chime:GetGlobalSettings", "chime:GetEventsConfiguration", "chime:ListAccountUsageReportData", "chime:ListProxySessions", "chime:ListAccounts", "chime:ListCDRBucket", "chime:ListCallingRegions", "chime:ListSipRules", "chime:ListAttendeeTags", "chime:ListSupportedPhoneNumberCountries", "chime:GetCDRBucket", "chime:GetAttendee", "chime:ListPhoneNumbers", "chime:RetrieveDataExports", "chime:ListAttendees", "chime:ListApiKeys", "chime:GetMediaCapturePipeline", "chime:SearchAvailablePhoneNumbers", "chime:GetTelephonyLimits", "chime:ListBots", "chime:GetRoom", "chime:ListMediaCapturePipelines", "chime:ListPhoneNumberOrders", "chime:GetSipRule", "chime:GetPhoneNumberOrder", "chime:GetBot", "chime:ValidateAccountResource", "chime:ListRooms", "chime:GetDomain", "chime:ListDelegates", "chime:GetRetentionSettings", "chime:ListSipMediaApplications", "chime:GetPhoneNumberSettings", "chime:ListRoomMemberships", "codestar:Verify*", "cognito-sync:QueryRecords", "datapipeline:EvaluateExpression", "datapipeline:QueryObjects", "datapipeline:Validate*", "dax:BatchGetItem", "dax:GetItem", "dax:Query", "dax:Scan", "detective:SearchGraph", "dms:Test*", "ds:Check*", "ds:Verify*", "ds:DescribeCertificate", "ds:ListCertificates", "elastictranscoder:ListJobsByPipeline", "elastictranscoder:ListJobsByStatus", "kinesisvideo:GetClip", "kinesisvideo:GetDASHStreamingSessionURL", "kinesisvideo:GetHLSStreamingSessionURL", "lakeformation:GetTableObjects", "lakeformation:GetWorkUnitResults", "lakeformation:GetWorkUnits", "license-manager:GetAccessToken", "license-manager:GetGrant", "license-manager:ListTokens", "lightsail:GetContainerAPIMetadata", "lightsail:GetContainerImages", "lightsail:GetContainerLog", "lightsail:GetDiskSnapshot", "lightsail:GetDiskSnapshots", "lightsail:GetDistributionLatestCacheReset", "lightsail:GetDistributionMetricData", "lightsail:GetExportSnapshotRecords", "lightsail:GetInstanceAccessDetails", "lightsail:GetLoadBalancerMetricData", "lightsail:GetRelationalDatabaseEvents", "lightsail:GetRelationalDatabaseLogEvents", "lightsail:GetRelationalDatabaseMetricData", "lightsail:GetRelationalDatabaseSnapshot", "lightsail:GetRelationalDatabaseSnapshots", "logs:DescribeExportTasks", "logs:DescribeQueries", "logs:GetLogEvents", "logs:GetLogRecord", "logs:GetQueryResults", "macie2:GetFindings", "macie2:GetMacieSession", "macie2:GetUsageStatistics", "macie2:GetUsageTotals", "macie2:ListFindings", "polly:SynthesizeSpeech", "rekognition:CompareFaces", "wafv2:CheckCapacity", "workdocs:CheckAlias", "workmail:Search*", "cognito-identity:GetCredentialsForIdentity", "cognito-identity:GetIdentityPoolRoles", "cognito-identity:GetOpenId*", "cognito-idp:GetSigningCertificate", "connect:GetFederationToken", "secretsmanager:GetRandomPassword", "secretsmanager:GetSecretValue", "consolidatedbilling:*", "freetier:*", "invoicing:*", "payments:*"]
    resources = ["*"]

  }
}

resource "aws_iam_policy" "firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE" {
  name        = "firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE_document.json
  description = ""
}

data "aws_iam_policy_document" "AWSControlTowerAdminPolicy_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:DescribeAvailabilityZones"]
    resources = ["*"]

  }
}

resource "aws_iam_policy" "AWSControlTowerAdminPolicy" {
  name        = "AWSControlTowerAdminPolicy"
  path        = "/service-role/"
  policy      = data.aws_iam_policy_document.AWSControlTowerAdminPolicy_document.json
  description = "AWS Control Tower policy to manage AWS resources"
}

data "aws_iam_policy_document" "firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:*:767828760205:key/*"]

  }
  statement {
    effect    = "Deny"
    actions   = ["s3:GetObject"]
    resources = ["*"]

  }
}

resource "aws_iam_policy" "firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5" {
  name        = "firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5_document.json
  description = ""
}

data "aws_iam_policy_document" "firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:aws:events:us-east-1:094724549126:event-bus/prod-stablefly-event-bus"]

  }
}

resource "aws_iam_policy" "firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj" {
  name        = "firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj_document.json
  description = ""
}

data "aws_iam_policy_document" "AWSControlTowerStackSetRolePolicy_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/AWSControlTowerExecution"]

  }
}

resource "aws_iam_policy" "AWSControlTowerStackSetRolePolicy" {
  name        = "AWSControlTowerStackSetRolePolicy"
  path        = "/service-role/"
  policy      = data.aws_iam_policy_document.AWSControlTowerStackSetRolePolicy_document.json
  description = "AWS CloudFormation assumes this role to deploy stacksets in the shared AWS Control Tower accounts"
}

data "aws_iam_policy_document" "firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["events:ListTargetsByRule", "events:DescribeRule", "events:PutTargets", "events:PutRule", "events:RemoveTargets", "events:DeleteRule", "events:DisableRule", "events:TestEventPattern", "events:EnableRule", "events:TagResource"]
    resources = ["arn:aws:events:*:767828760205:rule/firefly-events-*"]

  }
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::767828760205:role/invoke-firefly-remote-event-bus"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["events.amazonaws.com"]
    }

  }
}

resource "aws_iam_policy" "firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO" {
  name        = "firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO_document.json
  description = ""
}

data "aws_iam_policy_document" "firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["glue:GetResourcePolicies"]
    resources = ["*"]

  }
  statement {
    effect    = "Allow"
    actions   = ["elasticmapreduce:GetAutoTerminationPolicy"]
    resources = ["arn:aws:elasticmapreduce:*:767828760205:cluster/*"]

  }
}

resource "aws_iam_policy" "firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v" {
  name        = "firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v_document.json
  description = ""
}

data "aws_iam_policy_document" "firefly-readonly-S3NotificationsPermissions-lnOuZMBE4vWz_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["s3:PutBucketNotification"]
    resources = ["arn:aws:s3:::*"]

  }
}

resource "aws_iam_policy" "firefly-readonly-S3NotificationsPermissions-lnOuZMBE4vWz" {
  name        = "firefly-readonly-S3NotificationsPermissions-lnOuZMBE4vWz"
  path        = "/"
  policy      = data.aws_iam_policy_document.firefly-readonly-S3NotificationsPermissions-lnOuZMBE4vWz_document.json
  description = ""
}

data "aws_iam_policy_document" "AWSControlTowerCloudTrailRolePolicy_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["arn:aws:logs:*:*:log-group:aws-controltower/CloudTrailLogs:*"]

  }
  statement {
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:log-group:aws-controltower/CloudTrailLogs:*"]

  }
}

resource "aws_iam_policy" "AWSControlTowerCloudTrailRolePolicy" {
  name        = "AWSControlTowerCloudTrailRolePolicy"
  path        = "/service-role/"
  policy      = data.aws_iam_policy_document.AWSControlTowerCloudTrailRolePolicy_document.json
  description = "AWS CloudTrail assumes this role to create and publish CloudTrail logs"
}

