-- Thread activity, follows, unread state, and follower notifications.

alter table public.threads
add column reply_count integer not null default 0
  check (reply_count >= 0),
add column last_post_at timestamp with time zone,
add column last_poster_id uuid references public.profiles(id) on delete set null;

update public.threads as thread
set reply_count = greatest(
      (
        select count(*)::integer - 1
        from public.posts
        where posts.thread_id = thread.id
      ),
      0
    ),
    last_post_at = (
      select posts.created_at
      from public.posts
      where posts.thread_id = thread.id
      order by posts.created_at desc, posts.id desc
      limit 1
    ),
    last_poster_id = (
      select posts.author_id
      from public.posts
      where posts.thread_id = thread.id
      order by posts.created_at desc, posts.id desc
      limit 1
    );

create index threads_last_poster_id_idx
on public.threads (last_poster_id)
where last_poster_id is not null;

drop index if exists public.threads_board_pagination_idx;

create index threads_board_pagination_idx
on public.threads (
  board_id,
  pinned desc,
  last_post_at desc nulls last,
  created_at desc,
  id desc
);

create table public.thread_follows (
  user_id uuid not null references public.profiles(id) on delete cascade,
  thread_id uuid not null references public.threads(id) on delete cascade,
  created_at timestamp with time zone not null default now(),
  primary key (user_id, thread_id)
);

create index thread_follows_thread_id_idx
on public.thread_follows (thread_id, user_id);

alter table public.thread_follows enable row level security;

revoke all on table public.thread_follows from public, anon, authenticated;
grant select, insert, delete on table public.thread_follows to authenticated;

create policy "members can view own thread follows"
on public.thread_follows
for select
to authenticated
using (user_id = (select auth.uid()));

create policy "members can follow threads"
on public.thread_follows
for insert
to authenticated
with check (user_id = (select auth.uid()));

create policy "members can unfollow threads"
on public.thread_follows
for delete
to authenticated
using (user_id = (select auth.uid()));

create table public.thread_reads (
  user_id uuid not null references public.profiles(id) on delete cascade,
  thread_id uuid not null references public.threads(id) on delete cascade,
  last_read_at timestamp with time zone not null default now(),
  primary key (user_id, thread_id)
);

create index thread_reads_thread_id_idx
on public.thread_reads (thread_id);

alter table public.thread_reads enable row level security;

revoke all on table public.thread_reads from public, anon, authenticated;
grant select, insert on table public.thread_reads to authenticated;
grant update (last_read_at) on table public.thread_reads to authenticated;

create policy "members can view own thread reads"
on public.thread_reads
for select
to authenticated
using (user_id = (select auth.uid()));

create policy "members can create own thread reads"
on public.thread_reads
for insert
to authenticated
with check (user_id = (select auth.uid()));

create policy "members can update own thread reads"
on public.thread_reads
for update
to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

-- Only the nested post-activity trigger may maintain calculated thread fields.
-- Direct member updates remain limited to an unlocked thread's title.
create or replace function public.protect_thread_moderation_fields()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (select auth.uid()) is null
     and current_user not in ('authenticated', 'anon') then
    return new;
  end if;

  if pg_trigger_depth() > 1 then
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
     or new.reply_count is distinct from old.reply_count
     or new.last_post_at is distinct from old.last_post_at
     or new.last_poster_id is distinct from old.last_poster_id
     or new.created_at is distinct from old.created_at then
    raise insufficient_privilege
      using message = 'Only administrators can change thread moderation fields.';
  end if;

  return new;
end;
$$;

revoke execute on function public.protect_thread_moderation_fields()
from public, anon, authenticated;

drop policy if exists "users can create unlocked unapproved threads"
on public.threads;

create policy "users can create unlocked unapproved threads"
on public.threads
for insert
to authenticated
with check (
  (select auth.uid()) = author_id
  and pinned = false
  and locked = false
  and is_approved_character = false
  and character_approved_at is null
  and character_approved_by is null
  and reply_count = 0
  and last_post_at is null
  and last_poster_id is null
);

create or replace function public.refresh_thread_activity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected_thread_id uuid;
begin
  affected_thread_id := coalesce(new.thread_id, old.thread_id);

  update public.threads
  set reply_count = greatest(
        (
          select count(*)::integer - 1
          from public.posts
          where posts.thread_id = affected_thread_id
        ),
        0
      ),
      last_post_at = (
        select posts.created_at
        from public.posts
        where posts.thread_id = affected_thread_id
        order by posts.created_at desc, posts.id desc
        limit 1
      ),
      last_poster_id = (
        select posts.author_id
        from public.posts
        where posts.thread_id = affected_thread_id
        order by posts.created_at desc, posts.id desc
        limit 1
      )
  where threads.id = affected_thread_id;

  return coalesce(new, old);
end;
$$;

revoke execute on function public.refresh_thread_activity()
from public, anon, authenticated;

drop trigger if exists refresh_thread_activity_on_post
on public.posts;

create trigger refresh_thread_activity_on_post
after insert or delete on public.posts
for each row
execute function public.refresh_thread_activity();

alter table public.notifications
drop constraint notifications_type_check;

alter table public.notifications
add constraint notifications_type_check
check (type in ('reply', 'mention', 'followed_reply'));

create or replace function public.notify_members_on_post()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.notifications (
    recipient_id,
    actor_id,
    type,
    thread_id,
    post_id
  )
  select
    threads.author_id,
    new.author_id,
    'reply',
    new.thread_id,
    new.id
  from public.threads
  where threads.id = new.thread_id
    and threads.author_id <> new.author_id
  on conflict (recipient_id, type, post_id) do nothing;

  insert into public.notifications (
    recipient_id,
    actor_id,
    type,
    thread_id,
    post_id
  )
  select
    thread_follows.user_id,
    new.author_id,
    'followed_reply',
    new.thread_id,
    new.id
  from public.thread_follows
  join public.threads
    on threads.id = thread_follows.thread_id
  where thread_follows.thread_id = new.thread_id
    and thread_follows.user_id <> new.author_id
    and thread_follows.user_id <> threads.author_id
  on conflict (recipient_id, type, post_id) do nothing;

  insert into public.notifications (
    recipient_id,
    actor_id,
    type,
    thread_id,
    post_id
  )
  select distinct
    profiles.id,
    new.author_id,
    'mention',
    new.thread_id,
    new.id
  from regexp_matches(
    new.content,
    '@([A-Za-z0-9_-]{3,30})',
    'g'
  ) as handles(handle)
  join public.profiles
    on lower(profiles.username) = lower(handles.handle[1])
  where profiles.id <> new.author_id
  on conflict (recipient_id, type, post_id) do nothing;

  return new;
end;
$$;

revoke execute on function public.notify_members_on_post()
from public, anon, authenticated;
