(call_expression
  function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
  arguments: (arguments) @args
  (#match? @method "^(findById|findByPk|findOne|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOneBy|findOneOrFail|findOneByOrFail|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|getById|findOneById|getOne|deleteOne|destroy)$")) @call
