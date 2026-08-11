-- Approved character portraits used on member profiles and roleplay posts.

alter table public.threads
add column character_avatar_url text,
add constraint threads_character_avatar_url_length
check (
  character_avatar_url is null
  or char_length(character_avatar_url) <= 2000
);

comment on column public.threads.character_avatar_url is
  'Public portrait URL for an approved character thread.';

create or replace function public.protect_character_avatar_updates()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.character_avatar_url is not distinct from old.character_avatar_url then
    return new;
  end if;

  if (select auth.uid()) is null
     and current_user not in ('authenticated', 'anon') then
    return new;
  end if;

  if exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  ) then
    return new;
  end if;

  if old.author_id is distinct from (select auth.uid())
     or old.is_approved_character is not true
     or new.author_id is distinct from old.author_id
     or new.is_approved_character is not true then
    raise insufficient_privilege
      using message = 'Only the owner can update an approved character picture.';
  end if;

  return new;
end;
$$;

revoke execute on function public.protect_character_avatar_updates()
from public, anon, authenticated;

create trigger protect_character_avatar_updates
before update of character_avatar_url on public.threads
for each row
execute function public.protect_character_avatar_updates();

-- Character threads can live in locked or staff-controlled boards after
-- approval, so use a narrowly scoped function instead of widening thread RLS.
create or replace function public.set_character_avatar(
  character_thread_id_input uuid,
  avatar_url_input text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  normalized_url text := nullif(btrim(avatar_url_input), '');
  updated_url text;
begin
  if (select auth.uid()) is null then
    raise insufficient_privilege
      using message = 'You must be signed in to update a character picture.';
  end if;

  if normalized_url is not null and (
    char_length(normalized_url) > 2000
    or normalized_url !~ '^https://'
  ) then
    raise check_violation
      using message = 'Character picture must use a valid HTTPS URL.';
  end if;

  update public.threads
  set character_avatar_url = normalized_url
  where id = character_thread_id_input
    and author_id = (select auth.uid())
    and is_approved_character = true
  returning character_avatar_url into updated_url;

  if not found then
    raise insufficient_privilege
      using message = 'Only the owner can update an approved character picture.';
  end if;

  return updated_url;
end;
$$;

revoke execute on function public.set_character_avatar(uuid, text)
from public, anon;

grant execute on function public.set_character_avatar(uuid, text)
to authenticated;
