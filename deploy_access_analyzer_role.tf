resource "aws_iam_role" "airiam_access_analyzer" {
  name = "AirIAM-AccessAnalyzer-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "access-analyzer.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "airiam_access_analyzer_policy" {
  name = "AirIAM-AccessAnalyzer-Policy"
  role = aws_iam_role.airiam_access_analyzer.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrail",
          "iam:Get*",
          "iam:List*"
        ],
        Resource = "*"
      }
    ]
  })
} 