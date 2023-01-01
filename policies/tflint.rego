package tflint

deny[ret] {
  instances := terraform.resources("aws_instance", {
    "instance_type": "string",
    "ebs_block_device": {
      "volume_size": "string"
    },
  })
  instances[i].config.instance_type == "t2.micro"

  ret := {
    "message": "Instance contains t2.micro",
    "severify": "error",
    "location": instances[i].def_range
  }
}
