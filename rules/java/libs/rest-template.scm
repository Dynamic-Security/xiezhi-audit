(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|put|delete|patchForObject|headForHeaders|optionsForAllow)$")) @call
