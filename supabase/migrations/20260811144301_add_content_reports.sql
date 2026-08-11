-- Private member reports and an administrator-only moderation queue.

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  target_type text not null check (
    target_type in ('post', 'thread', 'profile')
  ),
  target_post_id uuid,
  target_thread_id uuid,
  target_profile_id uuid,
  reason text not null check (
    reason in (
      'spam',
      'harassment',
      'inappropriate_content',
      'impersonation',
      'rule_violation',
      'suspected_alt',
      'other'
    )
  ),
  details text,
  status text not null default 'open' check (
    status in ('open', 'resolved', 'dismissed')
  ),
  created_at timestamp with time zone not null default now(),
  reviewed_at timestamp with time zone,
  reviewed_by uuid references public.profiles(id) on delete set null,
  resolution_note text,
  constraint reports_target_matches_type check (
    (
      target_type = 'post'
      and target_post_id is not null
      and target_thread_id is null
      and target_profile_id is null
    )
    or (
      target_type = 'thread'
      and target_post_id is null
      and target_thread_id is not null
      and target_profile_id is null
    )
    or (
      target_type = 'profile'
      and target_post_id is null
      and target_thread_id is null
      and target_profile_id is not null
    )
  ),
  constraint reports_details_length check (
    details is null or char_length(details) <= 2000
  ),
  constraint reports_resolution_note_length check (
    resolution_note is null or char_length(resolution_note) <= 2000
  ),
  constraint reports_review_state_consistent check (
    (
      status = 'open'
      and reviewed_at is null
      and reviewed_by is null
      and resolution_note is null
    )
    or (
      status in ('resolved', 'dismissed')
      and reviewed_at is not null
      and reviewed_by is not null
    )
  )
);

-- Preserve target identifiers even when reported content is later removed.
-- One open report per member and target avoids duplicate queue entries while
-- still allowing a new report after the earlier one has been reviewed.
create unique index reports_one_open_post_per_member
on public.reports (reporter_id, target_post_id)
where target_type = 'post' and status = 'open';

create unique index reports_one_open_thread_per_member
on public.reports (reporter_id, target_thread_id)
where target_type = 'thread' and status = 'open';

create unique index reports_one_open_profile_per_member
on public.reports (reporter_id, target_profile_id)
where target_type = 'profile' and status = 'open';

create index reports_queue_order
on public.reports (status, created_at desc);

create index reports_reporter_id_idx
on public.reports (reporter_id);

create index reports_reviewed_by_idx
on public.reports (reviewed_by)
where reviewed_by is not null;

alter table public.reports enable row level security;

revoke all on table public.reports from public, anon, authenticated;
grant insert, select, update on table public.reports to authenticated;

create policy "members can report other members content"
on public.reports
for insert
to authenticated
with check (
  reporter_id = (select auth.uid())
  and status = 'open'
  and reviewed_at is null
  and reviewed_by is null
  and resolution_note is null
  and (
    (
      target_type = 'post'
      and exists (
        select 1
        from public.posts
        where posts.id = reports.target_post_id
          and posts.author_id <> (select auth.uid())
      )
    )
    or (
      target_type = 'thread'
      and exists (
        select 1
        from public.threads
        where threads.id = reports.target_thread_id
          and threads.author_id <> (select auth.uid())
      )
    )
    or (
      target_type = 'profile'
      and exists (
        select 1
        from public.profiles
        where profiles.id = reports.target_profile_id
          and profiles.id <> (select auth.uid())
      )
    )
  )
);

create policy "admins can view reports"
on public.reports
for select
to authenticated
using (
  exists (
    select 1
    from public.profiles
    where profiles.id = (select auth.uid())
      and profiles.is_admin = true
  )
);

create policy "admins can update reports"
on public.reports
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
