(invocation_expression
  function: (member_access_expression
    expression: (_) @receiver
    name: [(identifier) @method (generic_name (identifier) @method)])
  arguments: (argument_list) @args
  (#match? @method "^(Find|FindAsync|GetById|GetByIdAsync|FindById|FindByIdAsync|DeleteById|DeleteByIdAsync|UpdateById|UpdateByIdAsync|First|FirstOrDefault|Single|SingleOrDefault|Where|FirstAsync|FirstOrDefaultAsync|SingleAsync|SingleOrDefaultAsync)$")) @call
