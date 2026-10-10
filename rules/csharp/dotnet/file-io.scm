(invocation_expression
  function: (member_access_expression
    expression: (_) @receiver
    name: [(identifier) @method (generic_name (identifier) @method)])
  arguments: (argument_list) @args
  (#match? @method "^(ReadAllText|ReadAllTextAsync|ReadAllBytes|ReadAllBytesAsync|ReadAllLines|ReadAllLinesAsync|ReadLines|OpenRead|OpenText|Open|OpenWrite|Create|WriteAllText|WriteAllTextAsync|WriteAllBytes|WriteAllBytesAsync|WriteAllLines|AppendAllText|AppendAllTextAsync|Delete|Copy|Move|Replace)$")) @call
