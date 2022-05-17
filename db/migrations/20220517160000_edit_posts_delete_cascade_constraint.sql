ALTER TABLE posts ADD CONSTRAINT what FOREIGN KEY (parent_id) REFERENCES posts(id);
ALTER TABLE posts DROP CONSTRAINT posts_parent_id_fkey;
ALTER TABLE posts RENAME CONSTRAINT what TO posts_parent_id_fkey;
