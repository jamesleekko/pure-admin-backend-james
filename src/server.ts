import app from "./app";
// import * as open from "open";
import config from "./config";
import * as dayjs from "dayjs";
import * as multer from "multer";
import { user, images } from "./models/mysql";
import Logger from "./loaders/logger";
import { queryTable, setCategory, setImageTypes } from "./utils/mysql";
const expressSwagger = require("express-swagger-generator")(app);
expressSwagger(config.options);

queryTable(user);
setCategory();
setImageTypes();
queryTable(images);

import {
  login,
  register,
  updateList,
  deleteList,
  searchPage,
  searchVague,
  upload,
  captcha,
  getAsyncRoutes,
  getArticleCategory,
  getImageTypes,
  refreshToken,
  updateImg,
  getImageList,
  deleteImage,
} from "./router/http";

app.delete("/deleteImage", (req,res)=>{
  deleteImage(req,res);
})

app.post("/imageList", (req, res) => {
  getImageList(req, res);
});

app.post("/login", (req, res) => {
  login(req, res);
});

app.post("/register", (req, res) => {
  register(req, res);
});

app.post("/refreshToken", (req, res) => {
  refreshToken(req, res);
});

app.get("/getAsyncRoutes", (req, res) => {
  getAsyncRoutes(req, res);
});

app.get("/getArticleCategory", (req, res) => {
  getArticleCategory(req, res);
});

app.get("/getImageTypes", (req, res) => {
  getImageTypes(req, res);
});

app.put("/updateList/:id", (req, res) => {
  updateList(req, res);
});

app.delete("/deleteList/:id", (req, res) => {
  deleteList(req, res);
});

app.post("/searchPage", (req, res) => {
  searchPage(req, res);
});

app.post("/searchVague", (req, res) => {
  searchVague(req, res);
});

// 新建存放临时文件的文件夹
const upload_tmp = multer({ dest: "upload_tmp/" });
app.post("/upload", upload_tmp.any(), (req, res) => {
  upload(req, res);
});

app.post("/updateImg", (req, res) => {
  updateImg(req, res);
});

app.get("/captcha", (req, res) => {
  captcha(req, res);
});

app.ws("/socket", function (ws, req) {
  ws.send(
    `${dayjs(new Date()).format("YYYY年MM月DD日HH时mm分ss秒")}成功连接socket`
  );

  // 监听客户端是否关闭socket
  ws.on("close", function (msg) {
    console.log("客户端已关闭socket", msg);
    ws.close();
  });

  // 监听客户端发送的消息
  ws.on("message", function (msg) {
    // 如果客户端发送close，服务端主动关闭该socket
    if (msg === "close") ws.close();

    ws.send(
      `${dayjs(new Date()).format(
        "YYYY年MM月DD日HH时mm分ss秒"
      )}接收到客户端发送的信息，服务端返回信息：${msg}`
    );
  });
});

app
  .listen(config.port, () => {
    Logger.info(`
    ################################################
    🛡️  Swagger文档地址: http://localhost:${config.port} 🛡️
    ################################################
  `);
  })
  .on("error", (err) => {
    Logger.error(err);
    process.exit(1);
  });

// open(`http://localhost:${config.port}`); // 自动打开默认浏览器
