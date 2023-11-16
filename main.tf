
locals {
  # user_data = <<-EOT
  #   #!/bin/bash
  #   sudo yum install httpd -y
  #   sudo systemctl enable httpd && sudo systemctl start httpd
  #   echo "hello world" >> /var/www/html/index.html
  #   sudo touch /var/www/html/health.txt
  #   echo "health status file" >> /var/www/html/health.txt
  # EOT
}


module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
  name    = "dev-vpc"
  cidr    = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = false
  enable_vpn_gateway = false

  tags = {
    Terraform   = "True"
    Environment = "Dev"
    Project     = "Couro"
  }
}



module "alb" {
  source             = "terraform-aws-modules/alb/aws"
  version            = "9.2.0"
  name               = "dev-alb"
  vpc_id             = module.vpc.vpc_id
  subnets            = module.vpc.private_subnets
  load_balancer_type = "application"

  # Security Group
  security_group_ingress_rules = {
    all_http = {
      from_port   = 80
      to_port     = 80
      ip_protocol = "tcp"
      description = "HTTP web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }
    all_https = {
      from_port   = 443
      to_port     = 443
      ip_protocol = "tcp"
      description = "HTTPS web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }
  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = "10.0.0.0/16"
    }
  }

  target_groups = {
    ex-instance = {
      name_prefix      = "tg-"
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
      create_attachment = false

      # health_check = {
      #   enabled             = false
      #   interval            = 30
      #   path                = "/health.txt"
      #   port                = "traffic-port"
      #   healthy_threshold   = 3
      #   unhealthy_threshold = 3
      #   timeout             = 6
      #   protocol            = "HTTP"
      #   matcher             = "200-399"
      # }
    }
  }

  listeners = {
    ex-http = {
      port     = 80
      protocol = "HTTP"

      forward = {
        target_group_key = "ex-instance"
      }
    }
  }


  tags = {
    Terraform   = "True"
    Environment = "Dev"
    Project     = "Couro"
  }
}

module "security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"
  vpc_id  = module.vpc.vpc_id
  name        = "couro-ec2-sg"
  description = "Security group for ec2 instances in asg"
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["https-443-tcp","http-80-tcp","ssh-tcp"]
  egress_rules = ["all-all"]

  tags = {
    Terraform   = "True"
    Environment = "Dev"
    Project     = "Couro"
  }
}

module "couro_dev_asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "7.2.0"

  # The name of the auto scaling group
  name = "couro-dev-asg"

  min_size                  = 1
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  target_group_arns         = [module.alb.target_groups["ex-instance"].arn]
  traffic_source_identifier = module.alb.target_groups["ex-instance"].arn
  create_traffic_source_attachment = true
  vpc_zone_identifier       = module.vpc.public_subnets
  key_name = "couro-pose-est-dev"
  security_groups = [module.security-group.security_group_id]
  # user_data         = base64encode(local.user_data)
  ebs_optimized     = true

  create_iam_instance_profile = true
  iam_role_name               = "EC2-SSM-Role"
  iam_role_path               = "/ec2/"
  iam_role_description        = "EC2 role for SSM"
  iam_role_tags = {
    CustomIamRole = "Yes"
  }
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }


  # Launch template
  launch_template_name        = "couro-dev-launch-template-asg"
  launch_template_description = "Launch template for couro dev asg"
  update_default_version      = true

  image_id          = "ami-0a6a65f85f27f6956"
  instance_type     = "t3.micro"
  enable_monitoring = true

  network_interfaces = [
    {
      delete_on_termination = true
      description           = "eth0"
      device_index          = 0
      security_groups       = [module.security-group.security_group_id]
      associate_public_ip_address = true
    }
  ]

  # block_device_mappings = [
  #   {
  #     # Root volume
  #     device_name = "/dev/xvda"
  #     no_device   = 0
  #     ebs = {
  #       delete_on_termination = true
  #       encrypted             = true
  #       volume_size           = 30
  #       volume_type           = "gp3"
  #     }
  #     }
  # ]

  scaling_policies = {
    my-policy = {
      policy_type = "TargetTrackingScaling"
      target_tracking_configuration = {
        predefined_metric_specification = {
          predefined_metric_type = "ASGAverageCPUUtilization"
        }
        target_value = 70.0
      }
    }
  }

  maintenance_options = {
    auto_recovery = "default"
  }

  # This will ensure imdsv2 is enabled, required, and a single hop which is aws security
  # best practices
  # See https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html#autoscaling-4
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Terraform   = "True"
    Environment = "Dev"
    Project     = "Couro"
  }

  # instance_refresh = {
  #   strategy = "Rolling"
  #   preferences = {
  #     checkpoint_delay       = 600
  #     checkpoint_percentages = [35, 70, 100]
  #     instance_warmup        = 300
  #     min_healthy_percentage = 50
  #   }
  #   triggers = ["tag"]
  # }

}

