export const permissionRoutes = [
  // {
  //   path: "/",
  //   name: "Home",
  //   // component: Layout,
  //   redirect: "/welcome",
  //   meta: {
  //     icon: "homeFilled",
  //     title: "首页",
  //     rank: 0
  //   },
  //   children: [
  //     {
  //       path: "/welcome",
  //       name: "Welcome",
  //       // component: () => import("@/views/welcome/index.vue"),
  //       meta: {
  //         title: "首页",
  //         roles: ["admin", "common"]
  //       }
  //     }
  //   ]
  // },
  // {
  //   path: "/article",
  //   meta: {
  //     title: "文章列表",
  //     icon: "article"
  //   },
  //   children: [
  //     {
  //       path: "/article/list",
  //       name: "Article",
  //       // component: () => import("@/views/article/index.vue"),
  //       meta: {
  //         title: "文章列表",
  //         roles: ["admin", "common"]
  //       }
  //     }
  //   ]
  // },
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