(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(authorize|authorize!|policy_scope|authorize_resource|verify_authorized|verify_policy_scoped|authenticate!|authenticate_[a-z_]+!|require_login|require_authentication|protected!|can\\?|cannot\\?)$")) @call
