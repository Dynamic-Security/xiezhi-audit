(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(setAmount|setPrice|setBalance|setTotal|setTotalAmount|setTotalPrice|setPayAmount|setQuantity|setCount|setStock|setDiscount|setPoints|setCredit|setScore)$")) @call
