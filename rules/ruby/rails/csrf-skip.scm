(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(skip_before_action|skip_forgery_protection|protect_from_forgery)$")) @call
