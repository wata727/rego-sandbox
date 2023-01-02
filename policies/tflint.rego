package tflint

is_invalid_instance_type(type) {
  type == data.instance_type
}

deny_invalid_instance[ret] {
  instances := terraform.resources("aws_instance", {
    "instance_type": "string",
    "ebs_block_device": {
      "volume_size": "string"
    },
  })
  is_invalid_instance_type(instances[i].config.instance_type)

  ret := {
    "message": sprintf("Instance contains %s", [data.instance_type]),
    "severify": "error",
    "location": instances[i].def_range
  }
}
