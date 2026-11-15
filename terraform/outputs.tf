output "region" {
  description = "Region Terraform is connected to"
  value       = data.aws_region.current.region
}