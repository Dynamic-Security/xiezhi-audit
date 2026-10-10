(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(setStatus|setState|setOrderStatus|setPayStatus|setAuditStatus|setApproveStatus|setApproved|setPaid|setRole|setRoles|setRoleId|setEnabled|setLocked|setDeleted|setOwner|setOwnerId|setUserId|setTenantId|updateStatus|changeStatus|updateState|updateRole)$")) @call
