# History of findings: key = check_id#resource#region
resource "aws_dynamodb_table" "findings" {
  name         = "scanner-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_key"

  attribute {
    name = "finding_key"
    type = "S"
  }
}