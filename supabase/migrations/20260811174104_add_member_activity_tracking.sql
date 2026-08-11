-- Track recent signed-in member activity for the forum homepage statistics.

alter table public.profiles
add column last_seen_at timestamp with time zone;

update public.profiles
set last_seen_at = now()
where last_seen_at is null;

create index profiles_last_seen_at_idx
on public.profiles (last_seen_at desc)
where last_seen_at is not null;

grant update (last_seen_at)
on public.profiles
to authenticated;

-- Members may touch only their own profile because of the existing profile
-- update RLS policy. Normalize the supplied value to database time so a
-- client cannot forge a future activity timestamp.
create or replace function public.normalize_member_last_seen()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.last_seen_at := now();
  return new;
end;
$$;

revoke execute on function public.normalize_member_last_seen()
from public, anon, authenticated;

create trigger normalize_member_last_seen_before_update
before update of last_seen_at
on public.profiles
for each row
execute function public.normalize_member_last_seen();
