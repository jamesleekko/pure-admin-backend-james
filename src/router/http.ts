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
import axios from "axios";

const utils = require("@pureadmin/utils");
const iconv = require("iconv-lite");
const mAxios = axios.create({
  timeout: 2000,
});

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

  const { id, title, type, content, time, tags } = req.body;
  if (id) {
    let sql: string =
      "UPDATE articles SET title = ?, type = ?, content = ?, time = ?, tags = ? WHERE id = ?";
    connection.query(
      sql,
      [title, type, content, time, tags, id],
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
      "INSERT INTO articles (title, type, content, time) VALUES (?, ?, ?, ?)";
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
  //请求可能包含type, name等参数, 不包含则查询所有
  const { type, name, page, size } = req.query;
  try {
    const list = await getList(type, name, page, size);
    const total = await getTotal();
    res.json({
      success: true,
      data: {
        list: list["data"],
        total: total["data"],
      },
    });
  } catch (error) {
    Logger.error(error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }

  function getList(type, name, page, size) {
    return new Promise((resolve, reject) => {
      //content字段查询前32个字符

      let sql: string =
        "SELECT id, title, type, views, likes, LEFT(content, 32) AS preview, time FROM articles";
      if (type && type != null && type != undefined) {
        if (sql.indexOf("WHERE") === -1) {
          sql += " WHERE type = " + mysql.escape(type);
        } else {
          sql += " AND type = " + mysql.escape(type);
        }
      }
      if (name && name != null && name != undefined) {
        if (sql.indexOf("WHERE") === -1) {
          sql += " WHERE title LIKE " + mysql.escape("%" + name + "%");
        } else {
          sql += " AND title LIKE " + mysql.escape("%" + name + "%");
        }
      }
      sql += " ORDER BY time DESC";
      if (page && size) {
        sql += " LIMIT " + (Number(page) - 1) * Number(size) + ", " + size;
      }
      connection.query(sql, function (err, data) {
        if (err) {
          Logger.error(err);
          reject(err);
        } else {
          resolve({
            success: true,
            data,
          });
        }
      });
    });
  }

  function getTotal() {
    return new Promise((resolve, reject) => {
      let sql: string = "SELECT COUNT(id) FROM articles";
      connection.query(sql, function (err, data) {
        if (err) {
          reject(err);
        } else {
          resolve({ success: true, data: data[0]["COUNT(id)"] });
        }
      });
    });
  }
};

const getArticleContent = async (req: Request, res: Response) => {
  const { id, isViewer } = req.query;
  let sql: string = "select * from articles WHERE id = ?";
  connection.query(sql, [id], function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data,
      });
      if (isViewer) {
        let sql: string = "UPDATE articles SET views = views + 1 WHERE id = ?";
        connection.query(sql, [id], function (err) {
          if (err) {
            Logger.error(err);
          }
        });
      }
    }
  });
};

const thumbArticle = async (req: Request, res: Response) => {
  const { id } = req.query;
  let sql: string = "UPDATE articles SET likes = likes + 1 WHERE id = ?";
  connection.query(sql, [id], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      //查询点赞数并返回
      let sql: string = "SELECT likes FROM articles WHERE id = ?";
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
    }
  });
};

const cancelThumb = async (req: Request, res: Response) => {
  const { id } = req.query;
  let sql: string = "UPDATE articles SET likes = likes - 1 WHERE id = ?";
  connection.query(sql, [id], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      //查询点赞数并返回
      let sql: string = "SELECT likes FROM articles WHERE id = ?";
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
    }
  });
};

const getQQInfo = async (req: Request, res: Response) => {
  const { qq } = req.query;
  const name_url = `https://r.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins=${qq}`;
  const avatar_url = `https://q2.qlogo.cn/headimg_dl?dst_uin=${qq}&spec=100`;
  // const name_res = await mAxios.get(name_url, {
  //   headers: {
  //     "X-Requested-With": "XMLHttpRequest",
  //     "Content-Type": "application/x-www-form-urlencoded",
  //   },
  // });

  //从第三方接口获取qq昵称
  const third_url = `https://api.7585.net.cn/qqtx/api.php?qq=${qq}&type=json`;
  let third_res;
  try {
    third_res = await mAxios.get(third_url, {
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
  } catch (e) {
    res.json({
      success: false,
      data: { message: Message[19] },
    });
  }
  // console.log("third", third_res.data);

  if (third_res.data.code === 1) {
    res.json({
      success: true,
      name: third_res.data.name,
      // name: JSON.parse(
      //   name_res.data.replace("portraitCallBack(", "").replace(")", "")
      // )[qq.toString()][6],
      avatar_url,
    });
  } else {
    res.json({
      success: false,
      data: { message: Message[19] },
    });
  }
};

const addComment = async (req: Request, res: Response) => {
  const {
    article_id,
    replyId,
    mainId,
    content,
    time,
    name,
    avatar,
    email,
    site,
  } = req.body;
  let sql: string =
    "INSERT INTO comments (article_id, replyId, mainId, content, time, name, avatar_url, email, site) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
  connection.query(
    sql,
    [article_id, replyId, mainId, content, time, name, avatar, email, site],
    function (err) {
      if (err) {
        Logger.error(err);
      } else {
        res.json({
          success: true,
          data: { message: Message[20] },
        });
      }
    }
  );
};

const getCommentById = async (req: Request, res: Response) => {
  try {
    const { id, page = 1, size = 10 } = req.query;
    const mainComments = await getMainComments(id, page, size);
    const commentsWithReply = await addReplyComments(mainComments);
    const commentsWithReplyTarget = await addReplyTargets(commentsWithReply);
    const totalCount = await getCommentCount(id);
    const mainCommentCount = await getMainCommentCount(id);

    res.json({
      success: true,
      data: {
        comments: commentsWithReplyTarget,
        total: totalCount,
        mainTotal: mainCommentCount,
      },
    });
  } catch (error) {
    Logger.error(error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
};

const getComments = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  try {
    const { page, size } = req.query;
    const list = await getCommentList(page, size);
    const total = await getCommentTotal();
    res.json({
      success: true,
      data: {
        list,
        total,
      },
    });
  } catch (e) {
    Logger.error(e);
    res.status(500).json({ success: false, error: "Internal server error" });
  }

  function getCommentList(page, size) {
    return new Promise((resolve, reject) => {
      let sql = "SELECT * FROM comments ORDER BY time DESC";
      if (page && size) {
        sql += " LIMIT " + (Number(page) - 1) * Number(size) + ", " + size;
      } else {
        sql += " LIMIT 0, 10";
      }
      connection.query(sql, function (err, data) {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  }

  function getCommentTotal() {
    return new Promise((resolve, reject) => {
      const sql = "SELECT COUNT(*) FROM comments";
      connection.query(sql, function (err, data) {
        if (err) {
          reject(err);
        } else {
          resolve(data[0]["COUNT(*)"]);
        }
      });
    });
  }
};

// 获取主评论
const getMainComments = (id, page, size) => {
  return new Promise((resolve, reject) => {
    const sql =
      "SELECT * FROM comments WHERE article_id = ? AND replyId IS NULL ORDER BY time DESC LIMIT ?, ?";
    connection.query(
      sql,
      [id, (Number(page) - 1) * Number(size), Number(size)],
      (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      }
    );
  });
};

// 添加回复评论
const addReplyComments = (mainComments) => {
  return Promise.all(
    mainComments.map((mainComment) => {
      return new Promise((resolve, reject) => {
        const sql =
          "SELECT * FROM comments WHERE mainId = ? AND replyId IS NOT NULL ORDER BY time DESC";
        connection.query(sql, [mainComment.id], (err, data) => {
          if (err) {
            reject(err);
          } else {
            mainComment.replyComments = data;
            resolve(mainComment);
          }
        });
      });
    })
  );
};

// 为回复评论添加回复对象
const addReplyTarget = (replyComments) => {
  return Promise.all(
    replyComments.map((replyComment) => {
      return new Promise((resolve, reject) => {
        const sql = "SELECT * FROM comments WHERE id = ?";
        connection.query(sql, [replyComment.replyId], (err, data) => {
          if (err) {
            reject(err);
          } else {
            replyComment.replyTarget = data[0];
            resolve(replyComment);
          }
        });
      });
    })
  );
};

//批量处理添加回复对象
const addReplyTargets = async (mainComments) => {
  const mainCommentsWithReply = await Promise.all(
    mainComments.map(async (mainComment) => {
      const replyCommentsWithTarget = await addReplyTarget(
        mainComment.replyComments
      );
      mainComment.replyComments = replyCommentsWithTarget;
      return mainComment;
    })
  );
  return mainCommentsWithReply;
};

// 获取评论总数
const getCommentCount = (id) => {
  return new Promise((resolve, reject) => {
    const sql = "SELECT COUNT(*) FROM comments WHERE article_id = ?";
    connection.query(sql, [id], (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data[0]["COUNT(*)"]);
      }
    });
  });
};

// 获取主评论总数
const getMainCommentCount = (id) => {
  return new Promise((resolve, reject) => {
    const sql =
      "SELECT COUNT(*) FROM comments WHERE article_id = ? AND replyId IS NULL";
    connection.query(sql, [id], (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data[0]["COUNT(*)"]);
      }
    });
  });
};

const deleteComment = async (req: Request, res: Response) => {
  let payload = null;
  try {
    const authorizationHeader = req.get("Authorization") as string;
    const accessToken = authorizationHeader.substr("Bearer ".length);
    payload = jwt.verify(accessToken, config.jwtSecret);
  } catch (error) {
    return res.status(401).end();
  }

  //获取url上的参数
  const idList = req.query.idList;
  let sql: string = "DELETE FROM comments WHERE id IN (?)";
  connection.query(sql, [idList], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data: { message: Message[20] },
      });
    }
  });
};

const getArticleGroup = async (req: Request, res: Response) => {
  const type = req.query.type as unknown as number;
  let sql: string = "SELECT id, title, type, time FROM articles";
  if (type == 1) {
    sql += " WHERE type = " + mysql.escape(type);
  }
  if (type == 2) {
    sql += " WHERE type = " + mysql.escape(type);
  }
  sql += " ORDER BY time DESC";
  connection.query(sql, function (err, data) {
    if (err) {
      Logger.error(err);
    } else {
      let resData = null;
      if (type == null || type == undefined) {
        resData = data;
      } else {
        resData = formatResByMonth(data);
      }
      res.json({
        success: true,
        data: resData,
      });
    }
  });

  function formatResByMonth(data) {
    //根据月份分组
    let group = {};
    data.forEach((item) => {
      let year = (item.time.getYear() + 1900) as string;
      let month = (item.time.getMonth() + 1) as string;
      let year_month = (year + "-" + month) as string;
      if (group[year_month] == undefined) {
        group[year_month] = [];
      }
      group[year_month].push(item);
    });

    let res = [];
    for (let key in group) {
      res.push({
        year_month: key,
        articles: group[key],
      });
    }

    return res;
  }
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
  const idList = req.query.idList;
  let sql: string = "DELETE FROM articles WHERE id IN (?)";
  connection.query(sql, [idList], function (err) {
    if (err) {
      Logger.error(err);
    } else {
      res.json({
        success: true,
        data: { message: Message[18] },
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
  const { type, name } = req.query;
  let sql: string = "select * from images";
  if (type && type != null && type != undefined) {
    sql += " WHERE type = " + mysql.escape(type);
  }
  if (name && name != null && name != undefined) {
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
  const idList = req.query.idList;
  let sql: string = "DELETE FROM images WHERE id IN (?)";
  connection.query(sql, [idList], function (err) {
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

  //首页banner引用第三方api
  if (Number(type) === 1) {
    res.json({
      success: true,
      data: [{ src: "https://api.likepoems.com/img/bing" }],
      // data: [{ src: "https://api.cyrilstudio.top/bing/image.php?rand=true" }],
    });
    return;
  }

  //首页文章小图引用第三方api
  // if (Number(type) === 5) {
  //   mAxios.get("https://unsplash.it/1366/768?random").then((res) => {
  //     console.log("res", res.data);
  //   });
  //   res.json({
  //     success: true,
  //     data: [{ src: "https://unsplash.it/1366/768?random" }],
  //   });
  //   return;
  // }

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
  getArticleGroup,
  thumbArticle,
  cancelThumb,
  getQQInfo,
  getCommentById,
  getComments,
  addComment,
  deleteComment,
};
