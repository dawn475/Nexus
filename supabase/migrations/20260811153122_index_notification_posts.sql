-- Support notification cleanup when a referenced post is removed.

create index notifications_post_id_idx
on public.notifications (post_id);
