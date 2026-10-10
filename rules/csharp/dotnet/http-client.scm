(invocation_expression
  function: (member_access_expression
    expression: (_) @receiver
    name: [(identifier) @method (generic_name (identifier) @method)])
  arguments: (argument_list) @args
  (#match? @method "^(GetAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|GetFromJsonAsync|PostAsJsonAsync|PutAsJsonAsync|PatchAsJsonAsync|DeleteFromJsonAsync)$")) @call
