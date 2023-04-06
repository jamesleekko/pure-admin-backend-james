export const permissionRoutes = [
  {
    path: "/permission",
    meta: {
      title: "权限管理",
      icon: "lollipop",
      rank: 10
    },
    children: [
      {
        path: "/permission/page/index",
        name: "PermissionPage",
        meta: {
          title: "页面权限",
          roles: ["admin", "common"]
        }
      },
      {
        path: "/permission/button/index",
        name: "PermissionButton",
        meta: {
          title: "按钮权限",
          roles: ["admin"],
          auths: ["btn_add", "btn_edit", "btn_delete"]
        }
      }
    ]
  }
];