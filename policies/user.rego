package tflint

deny_banned_user[msg] {
  input.user == "wata727"
  msg := "You are banned"
}
