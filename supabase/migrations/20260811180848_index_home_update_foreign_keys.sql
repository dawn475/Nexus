-- Cover administrator attribution foreign keys used by homepage updates.

create index announcements_created_by_idx
on public.announcements (created_by);

create index forum_settings_updated_by_idx
on public.forum_settings (updated_by)
where updated_by is not null;
