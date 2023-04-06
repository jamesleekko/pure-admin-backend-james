import * as mysql from "mysql2";
import mysqlConfig from "../config";
import Logger from "../loaders/logger";
import { category } from "../models/mysql";
import * as jwt from "jsonwebtoken";
import secret from "../config";

/** blog数据库 */
export const connection = mysql.createConnection(
  Object.assign({ database: "blog" }, mysqlConfig.mysql)
);

export function queryTable(s: string): void {
  connection.query(s, (err) => {
    err ? Logger.error(err) : Logger.info(`${s}表存在`);
  });
}

export function setCategory(): void {
  queryTable(category);

  connection.query("select * from categories", (err, results) => {
    if (err) {
      Logger.error(err);
    } else {
      if (Array.isArray(results) && results.length === 0) {
        connection.query(
          "insert into categories (name) values ('开发笔记'),('胡言乱语')",
          (err) => {
            err ? Logger.error(err) : Logger.info("默认分类创建成功");
          }
        );
      }
    }
  });
}

export function generateRefreshToken(accountId: number) {
  const refreshToken = jwt.sign(
    {
      accountId: accountId,
    },
    secret.jwtSecret,
    { expiresIn: "1d" }
  );
  return refreshToken;
}