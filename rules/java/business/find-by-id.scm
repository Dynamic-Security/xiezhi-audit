(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(findById|findByIdAndDeletedFalse|getById|getOne|findOne|selectById|selectByPrimaryKey|deleteById|deleteByPrimaryKey|removeById|updateById|updateByPrimaryKey|updateByPrimaryKeySelective|loadById|queryById|detail|getDetail)$")) @call
