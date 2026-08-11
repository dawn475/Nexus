-- Let members post as one of their own approved characters while preserving
-- the account that owns and authored every post.

alter table public.posts
add column character_thread_id uuid
references public.threads(id)
on delete set null;

create index posts_character_thread_id_idx
on public.posts (character_thread_id)
where character_thread_id is not null;

create or replace function public.validate_post_character_identity()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.character_thread_id is not null
     and not exists (
       select 1
       from public.threads
       where threads.id = new.character_thread_id
         and threads.author_id = new.author_id
         and threads.is_approved_character = true
     ) then
    raise check_violation
      using message = 'Posts may only use an approved character owned by the post author.';
  end if;

  return new;
end;
$$;

revoke execute on function public.validate_post_character_identity()
from public, anon, authenticated;

create trigger validate_post_character_identity_before_write
before insert or update of author_id, character_thread_id
on public.posts
for each row
execute function public.validate_post_character_identity();
