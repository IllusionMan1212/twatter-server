CREATE OR REPLACE FUNCTION public.delete_post() RETURNS TRIGGER AS $$
	BEGIN
		UPDATE posts SET parent_deleted = true, parent_id = NULL WHERE parent_id = OLD.id;
    	RETURN OLD;
	END;
$$ language plpgsql;

CREATE OR REPLACE TRIGGER on_delete_post
BEFORE DELETE
ON posts
FOR EACH ROW EXECUTE FUNCTION public.delete_post()
