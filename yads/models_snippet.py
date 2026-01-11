
class UserTenantLink(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", primary_key=True)
