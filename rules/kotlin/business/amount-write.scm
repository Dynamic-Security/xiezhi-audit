(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(setAmount|setPrice|setBalance|setTotal|setTotalAmount|setTotalPrice|setPayAmount|setQuantity|setCount|setStock|setDiscount|setPoints|setCredit|setScore|updateBalance|updateAmount|addBalance|deductBalance)$")) @call
