[(call_expression
   (navigation_expression . (_) @receiver (identifier) @method .)
   (value_arguments) @args
   (#match? @method "^(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|put|delete|patchForObject|headForHeaders|optionsForAllow)$")) @call
 (binary_expression
   left: (binary_expression left: (navigation_expression . (_) @receiver (identifier) @method .))
   right: (parenthesized_expression) @args
   (#match? @method "^(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|put|delete|patchForObject|headForHeaders|optionsForAllow)$")) @call]
