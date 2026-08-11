-- Thread moderation permissions and locked-thread enforcement.

-- Public visitors never need direct write privileges. RLS remains enabled as
-- defense in depth, while authenticated members retain only the writes used by
-- the forum.
revoke insert, update, delete, truncate on table public.profiles
from anon;

revoke insert, update, delete, truncate on table public.threads
from anon;

revoke insert, update, delete, truncate on table public.posts
from anon;

-- Profiles contain protected account state. Members may edit only their
-- public-facing fields; currency and administrator status are maintained by
-- trusted database functions or project administrators.
revoke insert, update, delete, truncate on table public.profiles
from authenticated;

grant update (username, avatar_url, bio) on table public.profiles
to authenticated;

revoke truncate on table public.threads, public.posts
from authenticated;

-- Trigger functions should not be callable as public RPC endpoints. Vault and
-- store RPCs remain available only to signed-in members.
revoke execute on function public.award_currency_on_post()
from public, anon, authenticated;

revoke execute on function public.handle_new_user()
from public, anon, authenticated;

revoke execute on function public.deposit_currency(integer)
from public, anon;

revoke execute on function public.withdraw_currency(integer)
from public, anon;

revoke execute on function public.purchase_item(integer)
from public, anon;

grant execute on function public.deposit_currency(integer)
to authenticated;

grant execute on function public.withdraw_currency(integer)
to authenticated;

grant execute on function public.purchase_item(integer)
to authenticated;

drop policy if exists "users can update own profile"
on public.profiles;

create policy "users can update own public profile"
on public.profiles
for update
to authenticated
using ((select auth.uid()) = id)
with check ((select auth.uid()) = id);

-- Members create ordinary unlocked threads. Only administrators can later
-- move, pin, lock, or unlock them.
drop policy if exists "users can create threads"
on public.threads;

create policy "users can create unlocked threads"
on public.threads
for insert
to authenticated
with check (
  (select auth.uid()) = author_id
  and pinned = false
  and locked = false
);

drop policy if exists "authors or admins can update threads"
on public.threads;

create policy "admins can update threads"
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
)
with check (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
);

drop policy if exists "authors or admins can delete threads"
on public.threads;

create policy "authors can delete unlocked threads and admins can delete any"
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
  or (
    (select auth.uid()) = author_id
    and locked = false
  )
);

-- Locked threads remain readable, but only administrators may add, edit, or
-- remove posts until the thread is unlocked.
drop policy if exists "users can create posts"
on public.posts;

create policy "users can post in unlocked threads and admins can always post"
on public.posts
for insert
to authenticated
with check (
  (select auth.uid()) = author_id
  and exists (
    select 1
    from public.threads
    where threads.id = posts.thread_id
      and (
        threads.locked = false
        or exists (
          select 1
          from public.profiles
          where profiles.id = (select auth.uid())
            and profiles.is_admin = true
        )
      )
  )
);

drop policy if exists "authors or admins can update posts"
on public.posts;

create policy "authors can update posts in unlocked threads and admins can update any"
on public.posts
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
    (select auth.uid()) = author_id
    and exists (
      select 1
      from public.threads
      where threads.id = posts.thread_id
        and threads.locked = false
    )
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
    (select auth.uid()) = author_id
    and exists (
      select 1
      from public.threads
      where threads.id = posts.thread_id
        and threads.locked = false
    )
  )
);

drop policy if exists "authors or admins can delete posts"
on public.posts;

create policy "authors can delete posts in unlocked threads and admins can delete any"
on public.posts
for delete
to authenticated
using (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
  or (
    (select auth.uid()) = author_id
    and exists (
      select 1
      from public.threads
      where threads.id = posts.thread_id
        and threads.locked = false
    )
  )
);
