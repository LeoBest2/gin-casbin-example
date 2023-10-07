package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

/*
按如下约定:
  1. 所有策略只针对角色组设置
  2. 用户关联到组(一个用户可以有多个组)
+-------+-------+-----------+--------+----+----+----+
| ptype | v0    | v1        | v2     | v3 | v4 | v5 |
+-------+-------+-----------+--------+----+----+----+
| p     | admin | /api/user | GET    |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| p     | admin | /api/user | DELETE |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| p     | user  | /api/user | GET    |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| ...   | ...   | ...       |        |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| g     | leo   | admin     |        |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| g     | leo2  | admin     |        |    |    |    |
+-------+-------+-----------+--------+----+----+----+
| g     | leo3  | user      |        |    |    |    |
+-------+-------+-----------+--------+----+----+----+
*/
type CasbinService struct {
	enforcer *casbin.Enforcer
	adapter  *gormadapter.Adapter
}

func NewCasbinService(db *gorm.DB) (*CasbinService, error) {
	a, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, err
	}
	m, err := model.NewModelFromString(`[request_definition]
  r = sub, obj, act

  [policy_definition]
  p = sub, obj, act

  [role_definition]
  g = _, _

  [policy_effect]
  e = some(where (p.eft == allow))

  [matchers]
  m = g(r.sub, p.sub) && keyMatch2(r.obj,p.obj) && r.act == p.act`)
	if err != nil {
		return nil, err
	}
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, err
	}
	return &CasbinService{adapter: a, enforcer: e}, nil
}

// (RoleName, Url, Method) 对应于 `CasbinRule` 表中的 (v0, v1, v2)
type RolePolicy struct {
	RoleName string `gorm:"column:v0"`
	Url      string `gorm:"column:v1"`
	Method   string `gorm:"column:v2"`
}

// 获取所有角色组
func (c *CasbinService) GetRoles() []string {
	return c.enforcer.GetAllRoles()
}

// 获取所有角色组权限
func (c *CasbinService) GetRolePolicy() (roles []RolePolicy, err error) {
	err = c.adapter.GetDb().Model(&gormadapter.CasbinRule{}).Where("ptype = 'p'").Find(&roles).Error
	if err != nil {
		return nil, err
	}
	return
}

// 创建角色组权限, 已有的会忽略
func (c *CasbinService) CreateRolePolicy(r RolePolicy) error {
	// 不直接操作数据库，利用enforcer简化操作
	err := c.enforcer.LoadPolicy()
	if err != nil {
		return err
	}
	_, err = c.enforcer.AddPolicy(r.RoleName, r.Url, r.Method)
	if err != nil {
		return err
	}
	return c.enforcer.SavePolicy()
}

// 修改角色组权限
func (c *CasbinService) UpdateRolePolicy(old, new RolePolicy) error {
	_, err := c.enforcer.UpdatePolicy([]string{old.RoleName, old.Url, old.Method},
		[]string{new.RoleName, new.Url, new.Method})
	if err != nil {
		return err
	}
	return c.enforcer.SavePolicy()
}

// 删除角色组权限
func (c *CasbinService) DeleteRolePolicy(r RolePolicy) error {
	_, err := c.enforcer.RemovePolicy(r.RoleName, r.Url, r.Method)
	if err != nil {
		return err
	}
	return c.enforcer.SavePolicy()
}

type User struct {
	UserName  string
	RoleNames []string
}

// 获取所有用户以及关联的角色
func (c *CasbinService) GetUsers() (users []User) {
	p := c.enforcer.GetGroupingPolicy()
	usernameUser := make(map[string]*User, 0)
	for _, _p := range p {
		username, usergroup := _p[0], _p[1]
		if v, ok := usernameUser[username]; ok {
			usernameUser[username].RoleNames = append(v.RoleNames, usergroup)
		} else {
			usernameUser[username] = &User{UserName: username, RoleNames: []string{usergroup}}
		}
	}
	for _, v := range usernameUser {
		users = append(users, *v)
	}
	return
}

// 角色组中添加用户, 没有组默认创建
func (c *CasbinService) UpdateUserRole(username, rolename string) error {
	_, err := c.enforcer.AddGroupingPolicy(username, rolename)
	if err != nil {
		return err
	}
	return c.enforcer.SavePolicy()
}

// 角色组中删除用户
func (c *CasbinService) DeleteUserRole(username, rolename string) error {
	_, err := c.enforcer.RemoveGroupingPolicy(username, rolename)
	if err != nil {
		return err
	}
	return c.enforcer.SavePolicy()
}

// 验证用户权限
func (c *CasbinService) CanAccess(username, url, method string) (ok bool, err error) {
	return c.enforcer.Enforce(username, url, method)
}
