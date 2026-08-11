-- Public member profiles, avatar uploads, and approved character records.

alter table public.profiles
add constraint profiles_bio_length
check (bio is null or char_length(bio) <= 2000);

alter table public.threads
add column is_approved_character boolean not null default false,
add column character_approved_at timestamp with time zone,
add column character_approved_by uuid references public.profiles(id)
  on delete set null,
add constraint threads_character_approval_consistent
check (
  (
    is_approved_character = false
    and character_approved_at is null
    and character_approved_by is null
  )
  or
  (
    is_approved_character = true
    and character_approved_at is not null
    and character_approved_by is not null
  )
);

create index threads_approved_characters_by_author
on public.threads (author_id, character_approved_at desc)
where is_approved_character = true;

create index threads_character_approved_by_idx
on public.threads (character_approved_by)
where character_approved_by is not null;

-- Members cannot mark their own new threads as approved. Administrators can
-- approve or revoke approval later through the existing admin update policy.
drop policy if exists "users can create unlocked threads"
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
);

-- Avatars are public forum images. Uploads are limited to images up to 2 MB,
-- and each member may manage files only inside their own user-id folder.
insert into storage.buckets (
  id,
  name,
  public,
  file_size_limit,
  allowed_mime_types
)
values (
  'avatars',
  'avatars',
  true,
  2097152,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
)
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "avatars are publicly readable"
on storage.objects;

create policy "avatars are publicly readable"
on storage.objects
for select
to public
using (bucket_id = 'avatars');

drop policy if exists "members can upload own avatar"
on storage.objects;

create policy "members can upload own avatar"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'avatars'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "members can update own avatar"
on storage.objects;

create policy "members can update own avatar"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'avatars'
  and owner_id = (select auth.uid())::text
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'avatars'
  and owner_id = (select auth.uid())::text
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "members can delete own avatar"
on storage.objects;

create policy "members can delete own avatar"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'avatars'
  and owner_id = (select auth.uid())::text
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
