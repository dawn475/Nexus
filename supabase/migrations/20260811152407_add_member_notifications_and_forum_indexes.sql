-- Private reply/mention notifications and indexes for forum pagination/search.

-- Usernames double as mention handles. Case-insensitive uniqueness prevents
-- two members from sharing the same @handle with different capitalization.
alter table public.profiles
add constraint profiles_username_mention_format
check (username ~ '^[A-Za-z0-9_-]{3,30}$');

create unique index profiles_username_lower_key
on public.profiles (lower(username));

create index threads_board_pagination_idx
on public.threads (board_id, pinned desc, created_at desc, id desc);

create index threads_title_search_idx
on public.threads using gin (to_tsvector('simple', title));

create index posts_thread_pagination_idx
on public.posts (thread_id, created_at, id);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  actor_id uuid references public.profiles(id) on delete set null,
  type text not null check (type in ('reply', 'mention')),
  thread_id uuid not null references public.threads(id) on delete cascade,
  post_id uuid not null references public.posts(id) on delete cascade,
  created_at timestamp with time zone not null default now(),
  read_at timestamp with time zone,
  constraint notifications_not_self check (
    actor_id is null or actor_id <> recipient_id
  ),
  constraint notifications_one_type_per_post unique (
    recipient_id,
    type,
    post_id
  )
);

create index notifications_recipient_inbox_idx
on public.notifications (recipient_id, created_at desc);

create index notifications_recipient_unread_idx
on public.notifications (recipient_id, created_at desc)
where read_at is null;

create index notifications_actor_id_idx
on public.notifications (actor_id)
where actor_id is not null;

create index notifications_thread_id_idx
on public.notifications (thread_id);

alter table public.notifications enable row level security;

revoke all on table public.notifications from public, anon, authenticated;
grant select on table public.notifications to authenticated;
grant update (read_at) on table public.notifications to authenticated;

create policy "members can view own notifications"
on public.notifications
for select
to authenticated
using (recipient_id = (select auth.uid()));

create policy "members can update own notification read state"
on public.notifications
for update
to authenticated
using (recipient_id = (select auth.uid()))
with check (recipient_id = (select auth.uid()));

create or replace function public.notify_members_on_post()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- A reply alerts the thread starter, except for their own posts.
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

  -- Mentions are case-insensitive and may appear more than once in a post;
  -- DISTINCT plus the unique constraint produces one notification per member.
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

drop trigger if exists notify_members_on_post
on public.posts;

create trigger notify_members_on_post
after insert on public.posts
for each row
execute function public.notify_members_on_post();

alter publication supabase_realtime
add table public.notifications;
