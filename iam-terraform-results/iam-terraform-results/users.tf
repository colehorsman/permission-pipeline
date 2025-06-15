resource "aws_iam_user" "air-iam-user" {
  name          = "air-iam-user"
  path          = "/"
  force_destroy = true

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}
resource "aws_iam_user_policy_attachment" "air-iam-user_AdministratorAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  user       = aws_iam_user.air-iam-user.name
}
resource "aws_iam_user_group_membership" "air-iam-user_group_attachment" {
  user = aws_iam_user.air-iam-user.name

  groups = []
}
resource "aws_iam_user" "cole" {
  name          = "cole"
  path          = "/"
  force_destroy = true

  tags = {
    "rotate"          = "weekly"
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}
resource "aws_iam_user_policy_attachment" "cole_AdministratorAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  user       = aws_iam_user.cole.name
}
resource "aws_iam_user_policy_attachment" "cole_AWSOrganizationsFullAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess"
  user       = aws_iam_user.cole.name
}
resource "aws_iam_user_group_membership" "cole_group_attachment" {
  user = aws_iam_user.cole.name

  groups = []
}
resource "aws_iam_user" "grocery-app" {
  name          = "grocery-app"
  path          = "/"
  force_destroy = true

  tags = {
    "Managed by"      = "AirIAM by Bridgecrew"
    "Managed through" = "Terraform"
  }
}
resource "aws_iam_user_policy_attachment" "grocery-app_AdministratorAccess_managed" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  user       = aws_iam_user.grocery-app.name
}
resource "aws_iam_user_group_membership" "grocery-app_group_attachment" {
  user = aws_iam_user.grocery-app.name

  groups = []
}
