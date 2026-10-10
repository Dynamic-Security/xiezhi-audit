(call_expression
  function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
  arguments: (arguments) @args
  (#match? @method "^(where|andWhere|orWhere|having|andHaving|orHaving|orderBy|addOrderBy|groupBy|addSelect|select|leftJoinAndSelect|innerJoinAndSelect|setParameter)$")) @call
