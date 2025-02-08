CREATE TABLE users(
  id SERIAL PRIMARY KEY,
  username VARCHAR(100),
  password_hash VARCHAR(100),
  email VARCHAR(100)
);
