terraform {
  backend "s3" {
    bucket                  = "couro-terraform"
    key                     = "couro-dev/terraform.tfstate"
    region                  = "us-east-1"
    encrypt                 = true
    dynamodb_table          = "terraform-state-lock"
    shared_credentials_files = ["C:\\Users\\IhteshamUlHaq\\.aws\\credentials"]
    profile                 = "couro"
  }
}