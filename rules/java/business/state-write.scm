(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(setStatus|setState|setOrderStatus|setPayStatus|setAuditStatus|setApproveStatus|setApproved|setPaid|setRole|setRoles|setRoleId|setEnabled|setLocked|setDeleted|setOwner|setOwnerId|setUserId|setTenantId)$")) @call
