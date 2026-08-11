-- New character approvals may only be granted from World of the Living.
-- Revocation remains available after an approved thread is moved for sorting.

create or replace function public.restrict_character_approval_board()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.is_approved_character is true
     and old.is_approved_character is false
     and not exists (
       select 1
       from public.boards
       where boards.id = new.board_id
         and lower(btrim(boards.name)) = 'world of the living'
     ) then
    raise check_violation
      using message =
        'Characters can only be approved in World of the Living.';
  end if;

  return new;
end;
$$;

revoke execute on function public.restrict_character_approval_board()
from public, anon, authenticated;

create trigger restrict_character_approval_board
before update of is_approved_character on public.threads
for each row
execute function public.restrict_character_approval_board();
