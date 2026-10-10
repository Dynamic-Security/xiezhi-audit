(call_expression
  function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
  arguments: (arguments) @args
  (#match? @method "^(update|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate|increment|decrement|upsert|save|persist)$")) @call
