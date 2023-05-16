import * as fs from "fs";
import * as path from "path";
import * as uuid from "uuid";
import config from "../config";
import * as mysql from "mysql2";
import * as jwt from "jsonwebtoken";
import { createHash } from "crypto";
import Logger from "../loaders/logger";
import { Message } from "../utils/enums";
import getFormatDate from "../utils/date";
import { connection } from "../utils/mysql";
import { permissionRoutes } from "../utils/permissionRoutes";
import { Request, Response } from "express";
import { createMathExpr } from "svg-captcha";
import { generateRefreshToken } from "../utils/mysql";

const utils = require("@pureadmin/utils");

/** 保存验证码 */
let generateVerify: number;

/** 过期时间 单位：毫秒 默认 1分钟过期，方便演示 */
let expiresIn = 60 * 1000;

/**
 * @typedef Error
 * @property {string} code.required
 */

/**
 * @typedef Response
 * @property {[integer]} code
 */

// /**
//  * @typedef Login
//  * @property {string} username.required - 用户名 - eg: admin
//  * @property {string} password.required - 密码 - eg: admin123
//  * @property {integer} verify.required - 验证码
//  */

/**
 * @typedef Login
 * @property {string} username.required - 用户名
 * @property {string} password.required - 密码
 */

/**
 * @route POST /login
 * @param {Login.model} point.body.required - the new point
 * @produces application/json application/xml
 * @consumes application/json application/xml
 * @summary 登录
 * @group 用户登录、注册相关
 * @returns {Response.model} 200
 * @returns {Array.<Login>} Login
 * @headers {integer} 200.X-Rate-Limit
 * @headers {string} 200.X-Expires-After
 * @security JWT
 */

const login = async (req: Request, res: Response) => {
  // debugger
  // const { username, password, verify } = req.body;
  // if (generateVerify !== verify) return res.json({
  //   success: false,
  // data: {
  //   message: Message[0];
  // }
  // })
  const { username, password } = req.body;
  let sql: string =
    "select * from users where username=" + "'" + username + "'";
  connection.query(sql, async function (err, data: any) {
    if (data.length == 0) {
      await res.json({
        success: false,
        data: { message: Message[1] },
      });
    } else {
      let md5psw = createHash("md5").update(password).digest("hex");
      if (md5psw == data[0].password) {
        const accessToken = jwt.sign(
          {
            accountId: data[0].id,
          },
          config.jwtSecret,
          { expiresIn }
        );
        if (username === "admin") {
          const refreshtoken_admin = generateRefreshToken(data[0].id);
          await res.json({
            success: true,
            data: {
              message: Message[2],
              username,
              // 这里模拟角色，根据自己需求修改
              roles: ["admin"],
              accessToken,
              // 这里模拟刷新token，根据自己需求修改
              refreshToken: refreshtoken_admin,
              expires: new Date(new Date()).getTime() + expiresIn,
              // 这个标识是真实后端返回的接口，只是为了演示
              pureAdminBackend: "后端连通标识",
            },
          });
        } else {
          const refreshtoken_common = generateRefreshToken(data[0].id);
          await res.json({
            success: true,
            data: {
              message: Message[2],
              username,
              // 这里模拟角色，根据自己需求修改
              roles: ["common"],
              accessToken,
              // 这里模拟刷新token，根据自己需求修改
              refreshToken: refreshtoken_common,
              expires: new Date(new Date()).getTime() + expiresIn,
              // 这个标识是真实后端返回的接口，只是为了演示
              pureAdminBackend: "后端连通标识",
            },
          });
        }
      } else {
        await res.json({
          success: false,
          data: { message: Message[3] },
        });
      }
    }
  });
};

const refreshToken = async (req: Request, res: Response) => {
  const { refreshToken, username } = req.body;
  let payload = null;
  try {
    payload = jwt.verify(refreshToken, config.jwtSecret);
  } catch (error) {
    await res.json({
      success: false,
      data: { message: Message[12] },
    });
  }
  if (payload.exp && payload.exp > new Date().getTime() / 1000) {
    //find acccountId by username
    let sql: string =
      "select * from users where username=" + "'" + username + "'";
    connection.query(sql, async function (err, data: any) {
      if (data.length == 0) {
        await res.json({
          success: false,
          data: { message: Message[1] },
        });
      } else {
        const refreshtoken_new = generateRefreshToken(data[0].id);
        const accessToken = jwt.sign(
          {
            accountId: data[0].id,
          },
          config.jwtSecret,
          { expiresIn }
        );
        await res.json({
          success: true,
          data: {
            accessToken,
            refreshToken: refreshtoken_new,
            expires: new Date(new Date()).getTime() + expiresIn,
          },
        });
      }
    });
  } else {
    await res.json({
      success: false,
      data: { message: Message[13] },
    });
  }
};

// /**
//  * @typedef Register
//  * @property {string} username.required - 用户名
//  * @property {string} password.required - 密码
//  * @property {integer} verify.required - 验证码
//  */
/**
 * @typedef Register
 * @property {string} username.required - 用户名
 * @property {string} password.required - 密码
 */

/**
 * @route POST /register
 * @param {Register.model} point.body.required - the new point
 * @produces application/json application/xml
 * @consumes application/json application/xml
 * @summary 注册
 * @group 用户登录、注册相关
 * @returns {Response.model} 200
 * @returns {Array.<Register>} Register
 * @headers {integer} 200.X-Rate-Limit
 * @headers {string} 200.X-Expires-After
 * @security JWT
 */

const register = async (req: Request, res: Response) => {
  // debugger
  // const { username, password, verify } = req.body;
  const { username, password } = req.body;
  // if (generateVerify !== verify)
  //   return res.json({
  //     success: false,
  //     data: { message: Message[0] },
  //   });
  if (password.length < 6)
    return res.json({
      success: false,
      data: { message: Message[4] },
    });
  let sql: string =
    "select * from users where username=" + "'" + username + "'";
  connection.query(sql, async (err, data: any) => {
    if (data.length > 0) {
      await res.json({
        success: false,
        data: { message: Message[5] },
      });
    } else {
      let time = await getFormatDate();
      let sql: string =
        "insert into users (username,password,time) value(" +
        "'" +
        username +
        "'" +
        "," +
        "'" +
        createHash("md5").update(password).digest("hex") +
        "'" +
        "," +
        "'" +
        time +
        "'" +
        ")";
      connection.query(sql, async function (err) {
        if (err) {
          Logger.error(err);
        } else {
          await res.json({
            success: true,
            data: { message: Message[6] },
          });
        }
      });
    }
  });
};

const getAsyncRoutes = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }
  res.json({ success: true, data: permissionRoutes });
};

/**
 * @route GET /getArticleCategory
 * @summary 文章分类
 * @group 内容获取 - 文章分类
 * @returns {Array.<any>}
 */

const getArticleCategory = async (req: Request, res: Response) => {
  let sql: string = "select * from categories";
  connection.query(sql, async function (err, data) {
    if (err) {
      console.log(err);
    } else {
      await res.json({
        success: true,
        data: data,
      });
    }
  });
};

const getImageTypes = async (req: Request, res: Response) => {
  let sql: string = "select * from image_types";
  connection.query(sql, async function (err, data) {
    if (err) {
      console.log(err);
    } else {
      await res.json({
        success: true,
        data: data,
      });
    }
  });
};

/**
 * @typedef UpdateList
 * @property {string} username.required - 用户名 - eg: admin
 */

/**
 * @route PUT /updateList/{id}
 * @summary 列表更新
 * @param {UpdateList.model} point.body.required - 用户名
 * @param {UpdateList.model} id.path.required - 用户id
 * @group 用户管理相关
 * @returns {object} 200
 * @returns {Array.<UpdateList>} UpdateList
 * @security JWT
 */

const updateList = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { username } = req.body;
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }
  let modifySql: string = "UPDATE users SET username = ? WHERE id = ?";
  let sql: string = "select * from users where id=" + id;
  connection.query(sql, function (err, data) {
    connection.query(sql, function (err) {
      if (err) {
        Logger.error(err);
      } else {
        let modifyParams: string[] = [username, id];
        // 改
        connection.query(modifySql, modifyParams, async function (err, result) {
          if (err) {
            Logger.error(err);
          } else {
            await res.json({
              success: true,
              data: { message: Message[7] },
            });
          }
        });
      }
    });
  });
};

/**
 * @typedef DeleteList
 * @property {integer} id.required - 当前id
 */

/**
 * @route DELETE /deleteList/{id}
 * @summary 列表删除
 * @param {DeleteList.model} id.path.required - 用户id
 * @group 用户管理相关
 * @returns {object} 200
 * @returns {Array.<DeleteList>} DeleteList
 * @security JWT
 */

const deleteList = async (req: Request, res: Response) => {
  const { id } = req.params;
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }
  let sql: string = "DELETE FROM users where id=" + "'" + id + "'";
  connection.query(sql, async function (err, data) {
    if (err) {
      console.log(err);
    } else {
      await res.json({
        success: true,
        data: { message: Message[8] },
      });
    }
  });
};

/**
 * @typedef SearchPage
 * @property {integer} page.required - 第几页 - eg: 1
 * @property {integer} size.required - 数据量（条）- eg: 5
 */

/**
 * @route POST /searchPage
 * @param {SearchPage.model} point.body.required - the new point
 * @produces application/json application/xml
 * @consumes application/json application/xml
 * @summary 分页查询
 * @group 用户管理相关
 * @returns {Response.model} 200
 * @returns {Array.<SearchPage>} SearchPage
 * @headers {integer} 200.X-Rate-Limit
 * @headers {string} 200.X-Expires-After
 * @security JWT
 */

const searchPage = async (req: Request, res: Response) => {
  const { page, size } = req.body;
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }
  let sql: string =
    "select * from users limit " + size + " offset " + size * (page - 1);
  connection.query(sql, async function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      await res.json({
        success: true,
        data,
      });
    }
  });
};

/**
 * @typedef SearchVague
 * @property {string} username.required - 用户名  - eg: admin
 */

/**
 * @route POST /searchVague
 * @param {SearchVague.model} point.body.required - the new point
 * @produces application/json application/xml
 * @consumes application/json application/xml
 * @summary 模糊查询
 * @group 用户管理相关
 * @returns {Response.model} 200
 * @returns {Array.<SearchVague>} SearchVague
 * @headers {integer} 200.X-Rate-Limit
 * @headers {string} 200.X-Expires-After
 * @security JWT
 */

const searchVague = async (req: Request, res: Response) => {
  const { username } = req.body;
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }
  if (username === "" || username === null)
    return res.json({
      success: false,
      data: { message: Message[9] },
    });
  let sql: string = "select * from users";
  sql += " WHERE username LIKE " + mysql.escape("%" + username + "%");
  connection.query(sql, function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
    }
  });
};

// express-swagger-generator中没有文件上传文档写法，所以请使用postman调试
const upload = async (req: Request, res: Response) => {
  // 文件存放地址
  let currentuuid = "";
  let cur_des = "";
  const des_file: any = (index: number) => {
    currentuuid = uuid.v4();
    cur_des =
      "./public/files" +
      parseFilePath(req.body.file_type) +
      currentuuid +
      path.extname(req.files[index].originalname);
    return cur_des;
  };

  let filesLength = req.files.length as number;
  let result = [];

  function asyncUpload() {
    return new Promise((resolve, rejects) => {
      (req.files as Array<any>).forEach((ev, index) => {
        fs.readFile(req.files[index].path, function (err, data) {
          fs.writeFile(des_file(index), data, function (err) {
            if (err) {
              rejects(err);
            } else {
              while (filesLength > 0) {
                const fileName = uuid.v4() + path.extname(ev.originalname);
                result.push({
                  filename: req.files[filesLength - 1].originalname,
                  filepath: utils.getAbsolutePath(cur_des),
                  fileurl: `${req.protocol}://${req.hostname}:${
                    config.port
                  }/files${parseFilePath(
                    req.body.file_type
                  )}${currentuuid}${path.extname(ev.originalname)}`,
                });
                filesLength--;
              }
              if (filesLength === 0) resolve(result);
            }
          });
        });
      });
    });
  }

  function parseFilePath(type: string) {
    switch (type) {
      case "index-banner":
        return "/index-banner/";
      case "category-banner":
        return "/category-banner/";
      case "resource":
        return "/resource/";
      default:
        return "/";
    }
  }

  asyncUpload()
    .then((fileList) => {
      res.json({
        success: true,
        data: {
          message: Message[11],
          fileList,
        },
      });
    })
    .catch(() => {
      res.json({
        success: false,
        data: {
          message: Message[10],
          fileList: [],
        },
      });
    });
};

/**
 * @route GET /captcha
 * @summary 图形验证码
 * @group captcha - 图形验证码
 * @returns {object} 200
 */

const captcha = async (req: Request, res: Response) => {
  const create = createMathExpr({
    mathMin: 1,
    mathMax: 4,
    mathOperator: "+",
  });
  generateVerify = Number(create.text);
  res.type("svg"); // 响应的类型
  res.json({ success: true, data: { text: create.text, svg: create.data } });
};

const updateImg = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  const { id, title, imageType, imageUrl, time } = req.body;
  if (id) {
    let sql: string =
      "UPDATE images SET name = ?, type = ?, src = ?, time = ? WHERE id = ?";
    connection.query(
      sql,
      [title, imageType, imageUrl, time, id],
      function (err) {
        if (err) {
          Logger.error(err);
        } else {
          res.json({
            success: true,
            data: { message: Message[14] },
          });
        }
      }
    );
  } else {
    let sql: string =
      "INSERT INTO images (name, type, src, time) VALUES (?, ?, ?, ?)";
    connection.query(sql, [title, imageType, imageUrl, time], function (err) {
      if (err) {
        Logger.error(err);
      } else {
        res.json({
          success: true,
          data: { message: Message[15] },
        });
      }
    });
  }
};

const updateArticle = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  const { id, title, type, content, time } = req.body;
  if (id) {
    let sql: string =
      "UPDATE articles SET name = ?, type = ?, content = ?, time = ? WHERE id = ?";
    connection.query(
      sql,
      [title, type, content, time, id],
      function (err) {
        if (err) {
          Logger.error(err);
        } else {
          res.json({
            success: true,
            data: { message: Message[16] },
          });
        }
      }
    );
  } else {
    let sql: string =
      "INSERT INTO images (name, type, src, time) VALUES (?, ?, ?, ?)";
    connection.query(sql, [title, type, content, time], function (err) {
      if (err) {
        Logger.error(err);
      } else {
        res.json({
          success: true,
          data: { message: Message[17] },
        });
      }
    });
  }
};

const getArticleList = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  //请求可能包含type, name等参数, 不包含则查询所有
  const { type, name } = req.body;
  //查询除了content之外的所有字段
  let sql: string = "SELECT id, title, type, time FROM article";
  if (type != null && type != undefined) {
    sql += " WHERE type = " + mysql.escape(type);
  }
  if (name != null && name != undefined) {
    sql += " WHERE name LIKE " + mysql.escape("%" + name + "%");
  }
  //按时间降序排列
  sql += " ORDER BY time DESC";
  connection.query(sql, function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
    }
  });
};

const getArticleContent = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  const { id } = req.body;
  let sql: string = "select * from articles WHERE id = ?";
  connection.query(sql, [id], function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
    }
  });
};

const deleteArticle = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  //获取url上的参数
  const id = req.query.id;
  let sql: string = "DELETE FROM articles WHERE id = ?";
  connection.query(sql, [id], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
      });
    }
  });
};

const getImageList = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  //请求可能包含type, name等参数, 不包含则查询所有
  const { type, name } = req.body;
  let sql: string = "select * from images";
  if (type != null && type != undefined) {
    sql += " WHERE type = " + mysql.escape(type);
  }
  if (name != null && name != undefined) {
    sql += " WHERE name LIKE " + mysql.escape("%" + name + "%");
  }
  //按时间降序排列
  sql += " ORDER BY time DESC";
  connection.query(sql, function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
    }
  });
};

const deleteImage = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  //获取url上的参数
  const id = req.query.id;
  let sql: string = "DELETE FROM images WHERE id = ?";
  connection.query(sql, [id], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
      });
    }
  });
};

const getBannerImage = async (req: Request, res: Response) => {
  //根据bannertype随机获取一张图片的url
  const { type } = req.query;
  let sql: string =
    "SELECT src FROM images WHERE type = ? ORDER BY RAND() LIMIT 1";
  connection.query(sql, [type], function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
    }
  });
};

export {
  login,
  register,
  getAsyncRoutes,
  getArticleCategory,
  getImageTypes,
  updateList,
  deleteList,
  searchPage,
  searchVague,
  upload,
  captcha,
  refreshToken,
  updateImg,
  updateArticle,
  getArticleList,
  getArticleContent,
  deleteArticle,
  getImageList,
  deleteImage,
  getBannerImage,
};
