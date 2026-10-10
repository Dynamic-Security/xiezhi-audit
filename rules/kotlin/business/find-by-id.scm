(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(findById|findByIdOrNull|findByIdAndDeletedFalse|getById|getReferenceById|getOne|findOne|selectById|selectByPrimaryKey|deleteById|deleteByPrimaryKey|removeById|updateById|updateByPrimaryKey|loadById|queryById|getDetail)$")) @call
