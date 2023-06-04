/** 创建用户表 */
const user =
  "CREATE TABLE if not EXISTS users(id int PRIMARY key auto_increment,username varchar(32),password varchar(32),time DATETIME)";

const category =
  "CREATE TABLE if not EXISTS categories(id int PRIMARY key auto_increment,name varchar(32))";

const articles =
  "CREATE TABLE if not EXISTS articles(id int PRIMARY key auto_increment,title varchar(32),content text,type int,time DATETIME,views int,likes int)";

const image_types =
  "CREATE TABLE if not EXISTS image_types(id int PRIMARY key auto_increment,name varchar(32))";

const images =
  "CREATE TABLE if not EXISTS images(id int PRIMARY key auto_increment,name varchar(32),type int,src varchar(128),time DATETIME)";

export { user, category, image_types, images, articles };
