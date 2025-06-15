resource "aws_iam_role" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ" {
  name        = "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_FMS-PreReqManager-Policy" {
  name   = "FMS-PreReqManager-Policy"
  policy = data.aws_iam_policy_document.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_FMS-PreReqManager-Policy_document_document.json
  role   = aws_iam_role.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ.name
}

data "aws_iam_policy_document" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_FMS-PreReqManager-Policy_document_document" {
  version = "2012-10-17"
  statement {
    sid       = "CloudFormationWrite"
    effect    = "Allow"
    actions   = ["cloudformation:CreateStackInstances", "cloudformation:DeleteStackInstances"]
    resources = ["arn:aws:cloudformation:*:*:*/FMS-EnableConfig-Global:*", "arn:aws:cloudformation:*:*:*/FMS-EnableConfig-Regional:*", "arn:aws:cloudformation:*::type/resource/AWS-IAM-Role", "arn:aws:cloudformation:*::type/resource/AWS-SNS-Topic", "arn:aws:cloudformation:*::type/resource/AWS-S3-Bucket", "arn:aws:cloudformation:*::type/resource/AWS-SNS-TopicPolicy", "arn:aws:cloudformation:*::type/resource/AWS-SNS-Subscription", "arn:aws:cloudformation:*::type/resource/AWS-S3-BucketPolicy", "arn:aws:cloudformation:*::type/resource/AWS-Config-ConfigurationRecorder", "arn:aws:cloudformation:*::type/resource/AWS-Config-DeliveryChannel"]

  }
  statement {
    sid       = "GetOrgAdminRole"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:aws:iam::767828760205:role/aws-service-role/stacksets.cloudformation.amazonaws.com/AWSServiceRoleForCloudFormationStackSetsOrgAdmin"]

  }
  statement {
    sid       = "FMSAdmin"
    effect    = "Allow"
    actions   = ["fms:GetAdminAccount", "fms:AssociateAdminAccount"]
    resources = ["*"]

  }
  statement {
    sid       = "OrganizationsRead"
    effect    = "Allow"
    actions   = ["organizations:ListRoots", "organizations:DescribeOrganization", "organizations:DescribeAccount"]
    resources = ["*"]

  }
  statement {
    sid       = "OrganizationsWrite"
    effect    = "Allow"
    actions   = ["organizations:EnableAWSServiceAccess", "organizations:RegisterDelegatedAdministrator"]
    resources = ["*"]

  }
  statement {
    sid       = "PreReqRead0"
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions"]
    resources = ["*"]

  }
  statement {
    sid       = "PreReqWrite0"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole", "cloudformation:CreateStackSet", "ram:EnableSharingWithAwsOrganization", "cloudformation:ActivateOrganizationsAccess"]
    resources = ["*"]

  }
  statement {
    sid       = "XRayWriteAccess"
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets", "xray:GetSamplingStatisticSummaries"]
    resources = ["*"]

  }
}
resource "aws_iam_role_policy" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_PreReqManagerFunctionServiceRoleDefaultPolicy45CD6122" {
  name   = "PreReqManagerFunctionServiceRoleDefaultPolicy45CD6122"
  policy = data.aws_iam_policy_document.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_PreReqManagerFunctionServiceRoleDefaultPolicy45CD6122_document_document.json
  role   = aws_iam_role.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ.name
}

data "aws_iam_policy_document" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_PreReqManagerFunctionServiceRoleDefaultPolicy45CD6122_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]

  }
}
resource "aws_iam_role_policy_attachment" "aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ_AWSLambdaBasicExecutionRole_managed" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.aws-fms-prereq-PreReqManagerFunctionServiceRole3E27-qtm3xlthSxyQ.name
}

resource "aws_iam_role" "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1" {
  name        = "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_PreReqProviderframeworkonEventServiceRoleDefaultPolicy28F45022" {
  name   = "PreReqProviderframeworkonEventServiceRoleDefaultPolicy28F45022"
  policy = data.aws_iam_policy_document.aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_PreReqProviderframeworkonEventServiceRoleDefaultPolicy28F45022_document_document.json
  role   = aws_iam_role.aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1.name
}

data "aws_iam_policy_document" "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_PreReqProviderframeworkonEventServiceRoleDefaultPolicy28F45022_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:aws:lambda:us-east-1:767828760205:function:aws-fms-prereq-PreReqManagerFunction80D2ED4C-GOke494FYf9t", "arn:aws:lambda:us-east-1:767828760205:function:aws-fms-prereq-PreReqManagerFunction80D2ED4C-GOke494FYf9t:*"]

  }
}
resource "aws_iam_role_policy_attachment" "aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1_AWSLambdaBasicExecutionRole_managed" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.aws-fms-prereq-PreReqProviderframeworkonEventServic-yHjCgiGIBDe1.name
}

resource "aws_iam_role" "AWSControlTowerAdmin" {
  name        = "AWSControlTowerAdmin"
  path        = "/service-role/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.AWSControlTowerAdmin_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "AWSControlTowerAdmin_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["controltower.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "AWSControlTowerAdmin_AWSControlTowerServiceRolePolicy_managed" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSControlTowerServiceRolePolicy"
  role       = aws_iam_role.AWSControlTowerAdmin.name
}

resource "aws_iam_role" "AWSControlTowerConfigAggregatorRoleForOrganizations" {
  name        = "AWSControlTowerConfigAggregatorRoleForOrganizations"
  path        = "/service-role/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.AWSControlTowerConfigAggregatorRoleForOrganizations_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "AWSControlTowerConfigAggregatorRoleForOrganizations_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "AWSControlTowerConfigAggregatorRoleForOrganizations_AWSConfigRoleForOrganizations_managed" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
  role       = aws_iam_role.AWSControlTowerConfigAggregatorRoleForOrganizations.name
}

resource "aws_iam_role" "cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8" {
  name        = "cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8_assume_role_policy_document.json

  tags = {
    "Billing"         = "me"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8_LambdaPermissions" {
  name   = "LambdaPermissions"
  policy = data.aws_iam_policy_document.cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8_LambdaPermissions_document_document.json
  role   = aws_iam_role.cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8.name
}

data "aws_iam_policy_document" "cloudformation-nuke-stacks-LambdaExecutionRole-FUw0yWCHqTU8_LambdaPermissions_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["cloudformation:ListStacks", "cloudformation:DescribeStacks", "cloudformation:DeleteStack", "sns:Publish"]
    resources = ["*"]

  }
}

resource "aws_iam_role" "firefly-caa-role" {
  name        = "firefly-caa-role"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.firefly-caa-role_assume_role_policy_document.json

  tags = {
    "firefly"         = "true"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "firefly-caa-role_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::094724549126:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["MC41ODM0ODc2NDI1MDMxNDYz"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "firefly-caa-role_firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5" {
  policy_arn = aws_iam_policy.firefly-readonly-S3ReadPermissions-U9gzVqVQN8R5.arn
  role       = aws_iam_role.firefly-caa-role.name
}
resource "aws_iam_role_policy_attachment" "firefly-caa-role_firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE" {
  policy_arn = aws_iam_policy.firefly-readonly-FireflyReadonlyDenylist-5zX8xVHdBnjE.arn
  role       = aws_iam_role.firefly-caa-role.name
}
resource "aws_iam_role_policy_attachment" "firefly-caa-role_firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v" {
  policy_arn = aws_iam_policy.firefly-readonly-AdditionalFetchingPermissions-hVzphhT1B82v.arn
  role       = aws_iam_role.firefly-caa-role.name
}
resource "aws_iam_role_policy_attachment" "firefly-caa-role_firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO" {
  policy_arn = aws_iam_policy.firefly-readonly-EventbridgePermissions-yw9AzQ87XbHO.arn
  role       = aws_iam_role.firefly-caa-role.name
}
resource "aws_iam_role_policy_attachment" "firefly-caa-role_ReadOnlyAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
  role       = aws_iam_role.firefly-caa-role.name
}
resource "aws_iam_role_policy_attachment" "firefly-caa-role_SecurityAudit_managed" {
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  role       = aws_iam_role.firefly-caa-role.name
}

resource "aws_iam_role" "grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN" {
  name        = "grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN_CloudFrontFullAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/CloudFrontFullAccess"
  role       = aws_iam_role.grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN.name
}
resource "aws_iam_role_policy_attachment" "grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN_AmazonS3FullAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  role       = aws_iam_role.grocery-app-1747008327-CodeBuildServiceRole-Qex1bmsm4NuN.name
}

resource "aws_iam_role" "invoke-firefly-remote-event-bus" {
  name        = "invoke-firefly-remote-event-bus"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.invoke-firefly-remote-event-bus_assume_role_policy_document.json

  tags = {
    "firefly"         = "true"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "invoke-firefly-remote-event-bus_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "invoke-firefly-remote-event-bus_firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj" {
  policy_arn = aws_iam_policy.firefly-readonly-InvokeFireflyEventBusPolicy-LeMVcPDXEqEj.arn
  role       = aws_iam_role.invoke-firefly-remote-event-bus.name
}

resource "aws_iam_role" "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1" {
  name        = "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_assume_role_policy_document.json

  tags = {
    "billing"         = "true"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_IAMAccessKeyManagement" {
  name   = "IAMAccessKeyManagement"
  policy = data.aws_iam_policy_document.key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_IAMAccessKeyManagement_document_document.json
  role   = aws_iam_role.key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1.name
}

data "aws_iam_policy_document" "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_IAMAccessKeyManagement_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["iam:ListUsers", "iam:ListAccessKeys", "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey", "iam:ListUserTags", "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "sns:Publish"]
    resources = ["*"]

  }
}
resource "aws_iam_role_policy_attachment" "key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1_AWSLambdaBasicExecutionRole_managed" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.key-rotation-stack-LambdaExecutionRole-0tJHcmsdWpc1.name
}

resource "aws_iam_role" "LambdaVPCFlowLogRole" {
  name        = "LambdaVPCFlowLogRole"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.LambdaVPCFlowLogRole_assume_role_policy_document.json

  tags = {
    "billing"         = "yes"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "LambdaVPCFlowLogRole_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "LambdaVPCFlowLogRole_LambdaVPCFlowLogPolicy" {
  name   = "LambdaVPCFlowLogPolicy"
  policy = data.aws_iam_policy_document.LambdaVPCFlowLogRole_LambdaVPCFlowLogPolicy_document_document.json
  role   = aws_iam_role.LambdaVPCFlowLogRole.name
}

data "aws_iam_policy_document" "LambdaVPCFlowLogRole_LambdaVPCFlowLogPolicy_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["logs:StartQuery", "logs:GetQueryResults", "sns:Publish", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups"]
    resources = ["*"]

  }
}

resource "aws_iam_role" "root_monitor_lambda_role" {
  name        = "root_monitor_lambda_role"
  path        = "/"
  description = ""

  assume_role_policy = data.aws_iam_policy_document.root_monitor_lambda_role_assume_role_policy_document.json

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}

data "aws_iam_policy_document" "root_monitor_lambda_role_assume_role_policy_document" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "root_monitor_lambda_role_root_monitor_lambda_policy" {
  name   = "root_monitor_lambda_policy"
  policy = data.aws_iam_policy_document.root_monitor_lambda_role_root_monitor_lambda_policy_document_document.json
  role   = aws_iam_role.root_monitor_lambda_role.name
}

data "aws_iam_policy_document" "root_monitor_lambda_role_root_monitor_lambda_policy_document_document" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish", "organizations:ListRoots", "organizations:CreatePolicy", "organizations:AttachPolicy", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

  }
}

