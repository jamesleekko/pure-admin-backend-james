/** 创建用户表 */
const user =
  "CREATE TABLE if not EXISTS users(id int PRIMARY key auto_increment,username varchar(32),password varchar(32),time DATETIME)";

const category =
  "CREATE TABLE if not EXISTS categories(id int PRIMARY key auto_increment,name varchar(32))";

export { user, category };
