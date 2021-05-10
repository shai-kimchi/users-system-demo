NOTICE : YOU NEED PYTHON 3.7.0 TO RUN THIS PROJECT
1. Please Inject this lines in your MYSQL :
CREATE TABLE users ( username varchar(50) not null, email varchar(50) not null, password varchar(60), primary key (username) );
CREATE TABLE client(id int NOT NULL AUTO_INCREMENT,FirstName varchar(255),phone varchar(255),PRIMARY KEY (id));

For SQL Injection :	
Register : 
'asdasd','asdasd@asd.com','12345678');DROP TABLE users;#

Login:
'asd' OR 1=1#

Home:
'asdasd@asd.com','12345678');DROP TABLE client;#