(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(setStatus|setState|setAmount|setBalance|setPrice|setTotal|setRole|setRoles|setCredit|setPoints|setQuantity|setPaid|setApproved|setLevel|setDiscount)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(setStatus|setState|setAmount|setBalance|setPrice|setTotal|setRole|setRoles|setCredit|setPoints|setQuantity|setPaid|setApproved|setLevel|setDiscount)$")) @call
