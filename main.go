package main

import (
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	casbinService, err := NewCasbinService(db)
	if err != nil {
		panic("failed to new casbin service: " + err.Error())
	}

	r := gin.Default()
	auth := r.Group("/")
	auth.Use(NewCasbinAuth(casbinService))

	auth.GET("/api/user", func(ctx *gin.Context) {
		ctx.String(200, "get /api/user success")
	})

	auth.DELETE("/api/user", func(ctx *gin.Context) {
		ctx.String(200, "delete /api/user success")
	})

	// 获取所有用户
	auth.GET("/casbin/users", func(ctx *gin.Context) {
		ctx.JSON(200, casbinService.GetUsers())
	})

	// 获取所有角色组
	auth.GET("/casbin/roles", func(ctx *gin.Context) {
		ctx.JSON(200, casbinService.GetRoles())
	})

	// 获取所有角色组的策略
	auth.GET("/casbin/rolepolicy", func(ctx *gin.Context) {
		roles, err := casbinService.GetRolePolicy()
		if err != nil {
			ctx.String(500, "获取所有角色及权限失败: "+err.Error())
		} else {
			ctx.JSON(200, roles)
		}
	})

	/* 修改角色组策略
	  type RolePolicy struct {
	    RoleName string `gorm:"column:v0"`
	    Url      string `gorm:"column:v1"`
	    Method   string `gorm:"column:v2"`
	}
	*/
	auth.POST("/casbin/rolepolicy", func(ctx *gin.Context) {
		var p RolePolicy
		ctx.BindJSON(&p)
		err := casbinService.CreateRolePolicy(p)
		if err != nil {
			ctx.String(500, "创建角色策略失败: "+err.Error())
		} else {
			ctx.JSON(200, "成功!")
		}
	})

	/* 删除角色组策略
	  type RolePolicy struct {
	    RoleName string `gorm:"column:v0"`
	    Url      string `gorm:"column:v1"`
	    Method   string `gorm:"column:v2"`
	}
	*/
	auth.DELETE("/casbin/rolepolicy", func(ctx *gin.Context) {
		var p RolePolicy
		ctx.BindJSON(&p)
		err := casbinService.DeleteRolePolicy(p)
		if err != nil {
			ctx.String(500, "删除角色策略失败: "+err.Error())
		} else {
			ctx.JSON(200, "成功!")
		}
	})

	// 添加用户到组, /casbin/user-role?username=leo&useradd=leo99&rolename=admin
	// 第一个username=leo是简便起见鉴权，实际中不是这样，都是简便起见传递参数方式也可自己修改
	auth.POST("/casbin/user-role", func(ctx *gin.Context) {
		useradd := ctx.Query("useradd")
		rolename := ctx.Query("rolename")
		err := casbinService.UpdateUserRole(useradd, rolename)
		if err != nil {
			ctx.String(500, "添加用户到组失败: "+err.Error())
		} else {
			ctx.JSON(200, "成功!")
		}
	})

	// 从组中删除用户, /casbin/user-role?username=leo&useradd=leo99&rolename=admin
	// 第一个username=leo是简便起见鉴权，实际中不是这样，都是简便起见传递参数方式也可自己修改
	auth.DELETE("/casbin/user-role", func(ctx *gin.Context) {
		useradd := ctx.Query("useradd")
		rolename := ctx.Query("rolename")
		err := casbinService.DeleteUserRole(useradd, rolename)
		if err != nil {
			ctx.String(500, "从组中删除用户失败: "+err.Error())
		} else {
			ctx.JSON(200, "成功!")
		}
	})

	r.Run(":8000")
}
