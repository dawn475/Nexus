-- Board posting modes, homepage weather, and administrator announcements.

alter table public.boards
add column posting_mode text not null default 'open'
check (
  posting_mode in (
    'open',
    'admin_threads',
    'staff_only',
    'read_only'
  )
);

drop policy if exists "users can create unlocked unapproved threads"
on public.threads;

create policy "members can create threads according to board access"
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
  and exists (
    select 1
    from public.boards
    where boards.id = threads.board_id
      and (
        boards.posting_mode = 'open'
        or (
          boards.posting_mode in ('admin_threads', 'staff_only')
          and exists (
            select 1
            from public.profiles
            where profiles.id = (select auth.uid())
              and profiles.is_admin = true
          )
        )
      )
  )
);

drop policy if exists "authors can edit unlocked thread titles and admins can update threads"
on public.threads;

create policy "authors can edit allowed thread titles and admins can update threads"
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
    and exists (
      select 1
      from public.boards
      where boards.id = threads.board_id
        and boards.posting_mode = 'open'
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
    author_id = (select auth.uid())
    and locked = false
    and exists (
      select 1
      from public.boards
      where boards.id = threads.board_id
        and boards.posting_mode = 'open'
    )
  )
);

drop policy if exists "users can post in unlocked threads and admins can always post"
on public.posts;

create policy "members can post according to board access"
on public.posts
for insert
to authenticated
with check (
  (select auth.uid()) = author_id
  and exists (
    select 1
    from public.threads
    join public.boards
      on boards.id = threads.board_id
    where threads.id = posts.thread_id
      and boards.posting_mode <> 'read_only'
      and (
        (
          boards.posting_mode in ('open', 'admin_threads')
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
        or (
          boards.posting_mode = 'staff_only'
          and exists (
            select 1
            from public.profiles
            where profiles.id = (select auth.uid())
              and profiles.is_admin = true
          )
        )
      )
  )
);

drop policy if exists "authors can update posts in unlocked threads and admins can update any"
on public.posts;

create policy "authors can update allowed posts and admins can update any"
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
      join public.boards
        on boards.id = threads.board_id
      where threads.id = posts.thread_id
        and threads.locked = false
        and boards.posting_mode in ('open', 'admin_threads')
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
      join public.boards
        on boards.id = threads.board_id
      where threads.id = posts.thread_id
        and threads.locked = false
        and boards.posting_mode in ('open', 'admin_threads')
    )
  )
);

drop policy if exists "authors can delete posts in unlocked threads and admins can delete any"
on public.posts;

create policy "authors can delete allowed posts and admins can delete any"
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
      join public.boards
        on boards.id = threads.board_id
      where threads.id = posts.thread_id
        and threads.locked = false
        and boards.posting_mode in ('open', 'admin_threads')
    )
  )
);

create table public.forum_settings (
  id smallint primary key default 1 check (id = 1),
  season_title text not null default 'Current Season'
    check (char_length(season_title) <= 100),
  season_image_url text
    check (season_image_url is null or char_length(season_image_url) <= 1000),
  turn_label text not null default 'Turn —'
    check (char_length(turn_label) <= 100),
  months_label text not null default 'Months —'
    check (char_length(months_label) <= 100),
  weather_summary text not null default 'The forecast has not been updated yet.'
    check (char_length(weather_summary) <= 500),
  weather_details text not null default 'Check back soon for the complete forecast.'
    check (char_length(weather_details) <= 5000),
  updated_at timestamp with time zone not null default now(),
  updated_by uuid references public.profiles(id) on delete set null
);

insert into public.forum_settings (id)
values (1);

alter table public.forum_settings enable row level security;

revoke all on table public.forum_settings
from public, anon, authenticated;

grant select on table public.forum_settings
to public;

grant update (
  season_title,
  season_image_url,
  turn_label,
  months_label,
  weather_summary,
  weather_details,
  updated_at,
  updated_by
) on table public.forum_settings
to authenticated;

create policy "forum settings are viewable by everyone"
on public.forum_settings
for select
to public
using (true);

create policy "admins can update forum settings"
on public.forum_settings
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
  id = 1
  and updated_by = (select auth.uid())
  and exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
);

create table public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null check (
    char_length(title) between 1 and 160
  ),
  content text not null check (
    char_length(content) between 1 and 5000
  ),
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamp with time zone not null default now()
);

create index announcements_created_at_idx
on public.announcements (created_at desc, id desc);

alter table public.announcements enable row level security;

revoke all on table public.announcements
from public, anon, authenticated;

grant select on table public.announcements
to public;

grant insert, delete on table public.announcements
to authenticated;

create policy "announcements are viewable by everyone"
on public.announcements
for select
to public
using (true);

create policy "admins can publish announcements"
on public.announcements
for insert
to authenticated
with check (
  created_by = (select auth.uid())
  and exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
);

create policy "admins can delete announcements"
on public.announcements
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
