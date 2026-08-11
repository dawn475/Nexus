-- Allow members to edit only the titles of their own unlocked threads while
-- preserving all moderation fields for administrators.

create or replace function public.protect_thread_moderation_fields()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  -- Direct privileged database work is not performed through the member or
  -- anonymous API roles and should remain available to project operators.
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

  if new.author_id is distinct from old.author_id
     or new.board_id is distinct from old.board_id
     or new.pinned is distinct from old.pinned
     or new.locked is distinct from old.locked
     or new.is_approved_character is distinct from old.is_approved_character
     or new.character_approved_at is distinct from old.character_approved_at
     or new.character_approved_by is distinct from old.character_approved_by
     or new.created_at is distinct from old.created_at then
    raise insufficient_privilege
      using message = 'Only administrators can change thread moderation fields.';
  end if;

  return new;
end;
$$;

revoke execute on function public.protect_thread_moderation_fields()
from public, anon, authenticated;

drop trigger if exists protect_thread_moderation_fields
on public.threads;

create trigger protect_thread_moderation_fields
before update on public.threads
for each row
execute function public.protect_thread_moderation_fields();

drop policy if exists "admins can update threads"
on public.threads;

create policy "authors can edit unlocked thread titles and admins can update threads"
on public.threads
for update
to authenticated
using (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
  or (
    author_id = (select auth.uid())
    and locked = false
  )
)
with check (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
  or (
    author_id = (select auth.uid())
    and locked = false
  )
);

-- Whole threads are moderation records and may be deleted only by admins.
-- Members can still delete their own individual replies through the posts
-- policy, provided the thread is unlocked.
drop policy if exists "authors can delete unlocked threads and admins can delete any"
on public.threads;

create policy "admins can delete threads"
on public.threads
for delete
to authenticated
using (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
);
